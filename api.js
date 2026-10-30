// =====================================================
// CheddaBoards HTTP API Proxy v1.11.3
// Per-Game OAuth Credentials + Time-Based Scoreboards + Archives
// + Play Session Time Validation + Batch Achievement Unlocks
// + End Play Sessions + Account Migration
// + Board Read Caching + Pre-Actor Write Guard
// + Device Code Auth Flow (RFC 8628) + QR Code Generation
// + Skip-Validation Session Short-Circuit + 30s Board Read Cache
// + Fan-Out Board Submit Conversion + Helpful Unknown-Route 404s
// + Security audit fixes (2026-10-25): verified-email-only social login,
//   safe upgrade requests, real client IP, limits on unauthenticated routes
// =====================================================

import { Actor, HttpAgent } from "@dfinity/agent";
import { Ed25519KeyIdentity } from "@dfinity/identity";
import crypto from "crypto";
import { AsyncLocalStorage } from "node:async_hooks";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { memStore } from "./memstore.js";
import { idlFactory } from "./_lib/cheddaboards_v2_backend.did.js";
import QRCode from "qrcode";

// =====================================================
// Configuration
// =====================================================
const CANISTER_ID = process.env.CANISTER_ID;
if (!CANISTER_ID) throw new Error("CANISTER_ID environment variable is required");
const ICP_HOST = process.env.ICP_HOST || "https://icp-api.io";
const API_VERSION = "1.11.3";
// BUILD_STAMP changes on every edit. Hit /health after deploying: if the stamp
// you see live doesn't match this, the deploy did NOT take effect (stale bundle
// / cached function / wrong folder). This makes "did it actually redeploy?" a
// one-glance check instead of guesswork.
const BUILD_STAMP = "SOCIAL-AUTH-LIMITS-v1-2026-10-25";
logJson("[CheddaAPI] MODULE LOADED build=" + BUILD_STAMP, { evt: "module_loaded", build: BUILD_STAMP });

// Log hygiene: request paths and IDs are attacker-controlled — strip
// non-printables (raw bytes, newlines that would forge log lines) and cap
// length before they hit console.log.
function cleanForLog(s) {
  return String(s).replace(/[^\x20-\x7E]/g, "?").slice(0, 200);
}

// SINGLE INSTANCE ASSUMPTION: every limiter, cache and the device-code store
// in this file is per-process memory. The Cloud Run service MUST run with
// max-instances=1. A second instance silently halves every limit and breaks
// the device-code flow (code minted on one, polled on the other).

// Short stable fingerprint for values that act as credentials: external
// playerIds and anonymous deviceIds (anyone holding one plus the public API
// key can act as that player) and session tokens. Logs carry this instead of
// the raw value. Deterministic, so for a player ID a dev gives you:
//   node -e 'console.log(require("crypto").createHash("sha256").update(process.argv[1]).digest("hex").slice(0,12))' <playerId>
// and grep the logs for that.
function fp(v) {
  return crypto.createHash("sha256").update(String(v)).digest("hex").slice(0, 12);
}

// Bounded map insert. Replaces the old `if (map.size >= MAX) map.clear()`
// pattern: anyone able to mint new keys (rotating player IDs, junk API keys)
// could fill a map and wipe every other caller's rate-limit window at once.
// Sweeps expired entries first; if still full, drops the oldest 10%. Map
// iteration is insertion order, so callers starting a fresh window
// delete-then-set to move the key to the back.
function boundedSet(map, key, value, max, isExpired) {
  if (!map.has(key) && map.size >= max) {
    if (isExpired) {
      for (const [k, v] of map) if (isExpired(v)) map.delete(k);
    }
    if (map.size >= max) {
      let drop = Math.max(1, Math.floor(max / 10));
      for (const k of map.keys()) {
        map.delete(k);
        if (--drop <= 0) break;
      }
    }
  }
  map.set(key, value);
}

function envInt(name, dflt) {
  const v = parseInt(process.env[name] || "", 10);
  return Number.isFinite(v) ? v : dflt;
}

// Public board reads are capped server-side: the SDK defaults to 100 and no
// public consumer needs more. Clamp rather than 400 -- same philosophy as
// clampText on metadata -- so old clients asking for 1000 silently get the cap.
const MAX_BOARD_READ_LIMIT = 1000;
function parseLimit(query) {
  return Math.min(Math.max(parseInt(query.limit) || 100, 1), MAX_BOARD_READ_LIMIT);
}

// Structured log line: single-line JSON on stdout. Cloud Logging parses these
// into jsonPayload (filterable: jsonPayload.game, jsonPayload.evt, ...) with
// severity; on Netlify they render as plain JSON text (still greppable).
// logError() below is the ERROR-severity twin: same JSON shape, on stderr.
function logJson(message, fields = {}) {
  console.log(JSON.stringify({ severity: "INFO", message, ...fields }));
}

// Structured error line: severity ERROR to stderr (Cloud Run tags it ERROR and
// Cloud Logging still parses the JSON into jsonPayload). Pulls the agent error
// requestId out as hex when present so a gateway failure is traceable, instead
// of console.error dumping it as "[object ArrayBuffer]". Pass the caught error.
function logError(message, err, fields = {}) {
  const entry = { severity: "ERROR", message, err: err && (err.message || String(err)), ...fields };
  const rid = err && (err.requestId ?? (err.response && err.response.requestId));
  if (rid != null) {
    try {
      entry.requestId = (rid instanceof ArrayBuffer || ArrayBuffer.isView(rid))
        ? Buffer.from(rid.buffer ?? rid).toString("hex")
        : String(rid);
    } catch { entry.requestId = String(rid); }
  }
  console.error(JSON.stringify(entry));
}

// Short, client-safe reason for a failed canister call. Agent-js wraps IC
// rejects in a multi-line AgentError; pull out the reject message and IC
// error code so a 500 body says WHY. FIX 2026-09-29: play-session starts
// were failing for a day with "could not perform remote call" (the canister
// was at its cycles freezing threshold and couldn't fund raw_rand) and the
// client only ever saw "Failed to start play session".
function describeCanisterError(e) {
  const msg = (e && (e.message || String(e))) || "unknown error";
  // agent-js has used both  Reject message: 'x'  and  "Reject message": "x"
  const reject = msg.match(/Reject message"?:\s*["']([^"']*)["']/);
  const code = msg.match(/Error code"?:\s*["']?([A-Z][A-Z0-9]+)/);
  let out = reject ? reject[1] : msg.split("\n")[0];
  if (code) out += ` (${code[1]})`;
  return out.replace(/\s+/g, " ").trim().slice(0, 200);
}

// The proxy caches "this game has validation off" for SKIP_VALIDATION_TTL and
// mints skip_validation_ tokens locally. If validation is switched ON inside
// that window, the canister rejects those tokens on submit while the proxy
// keeps handing them out. Drop the cache entry the moment a skip token is
// rejected so the next start goes back to the canister.
function invalidateSkipCacheIfRejected(gameId, playSessionToken, err) {
  if (!gameId || !playSessionToken || typeof err !== "string") return;
  if (!playSessionToken.startsWith("skip_validation_")) return;
  if (!/session/i.test(err)) return;
  if (skipValidationGames.delete(gameId)) {
    logJson(`[PlaySession] Skip-validation cache dropped for ${cleanForLog(gameId)}: canister rejected a skip token ("${cleanForLog(err)}")`, { evt: "skip_cache_invalidated", game: cleanForLog(gameId), err: cleanForLog(err) });
  }
}

// Verifier signing identity. The canister gates privileged auth methods
// (socialLoginAndGetProfile, etc.) on caller == VERIFIER, so the proxy MUST
// sign its canister calls with this identity — otherwise it calls anonymously
// and is indistinguishable from an attacker forging an email. The secret is a
// serialized Ed25519KeyIdentity JSON, stored ONLY in the Netlify env var.
// Generate with generate-verifier-identity.mjs; never commit or log it.
//
// Parsed lazily inside getActor() (NOT at module top-level) so the build step,
// which may load the module without runtime env vars present, can't throw here.
let verifierIdentity = null;
function getVerifierIdentity() {
  if (verifierIdentity) return verifierIdentity;
  const json = process.env.VERIFIER_IDENTITY;
  if (!json) {
    throw new Error("VERIFIER_IDENTITY environment variable is required (serialized Ed25519 identity)");
  }
  try {
    verifierIdentity = Ed25519KeyIdentity.fromParsedJson(JSON.parse(json));
  } catch (err) {
    throw new Error("VERIFIER_IDENTITY is not a valid serialized Ed25519KeyIdentity JSON: " + err.message);
  }
  return verifierIdentity;
}

// Fallback credentials for games owned by whoever runs this proxy
const FALLBACK_GOOGLE_CLIENT_IDS = (process.env.GOOGLE_CLIENT_IDS || "").split(",").filter(Boolean);
const FALLBACK_APPLE_BUNDLE_ID = process.env.APPLE_BUNDLE_ID || "";

// Device code verification page credentials (CheddaBoards-owned, used for /link page)
const DEVICE_AUTH_GOOGLE_CLIENT_ID = process.env.DEVICE_AUTH_GOOGLE_CLIENT_ID || "";
const DEVICE_AUTH_APPLE_BUNDLE_ID = process.env.DEVICE_AUTH_APPLE_BUNDLE_ID || "";

// =====================================================
// Actor Creation
// =====================================================
let cachedAgent = null;
let cachedActor = null;
let lastActorCreation = 0;
const ACTOR_TTL = 5 * 60 * 1000;

// Cache for the public /stats counter so a marketing-page widget polling every
// few seconds doesn't hit the canister on every request.
let statsCache = null;
let statsCacheTime = 0;
const STATS_CACHE_TTL_MS = 30 * 1000;

// Rate guard for /request-upgrade so one dev can't spam upgrade emails.
// In-memory per warm function instance — good enough to blunt accidental
// double-clicks and casual spam; not a hard security control.
const upgradeRequestTimes = new Map();
const UPGRADE_REQUEST_COOLDOWN_MS = 5 * 60 * 1000;

// Public board reads are the highest-volume GETs on the platform (leaderboard
// scenes polling every few seconds). 30s of browser + Netlify CDN cache
// matches the SDK's 30s poll default, so steady polling collapses to ~1
// origin hit per 30s per board and the edge absorbs repeats across players.
// ONLY safe on routes whose content is fully identified by the URL -- never
// on anything session-authed. The Netlify-Vary: query line makes the CDN key
// on the query string too, so different ?limit= values never share a cache
// entry.
const CACHE_BOARD_READ = {
  "Cache-Control": "public, max-age=30",
  "Netlify-CDN-Cache-Control": "public, s-maxage=30",
  "Netlify-Vary": "query",
};

// /leaderboard is keyed by the X-Game-ID header (or api key / session), NOT
// the URL -- CDN caching it would serve one game's board to another. So:
// browser-only (private) caching, with Vary covering every header that
// selects the game. Fixes single-client poll hammering (the common case)
// while making cross-game contamination impossible.
const CACHE_LEADERBOARD = {
  "Cache-Control": "private, max-age=10",
  "Vary": "Origin, X-Game-ID, X-API-Key, X-Session-Token",
};

// Pre-actor write guard: mirrors the canister's per-(player, game, board) 2s
// submit cooldown at the very top of the request, BEFORE actor creation, so
// rapid duplicate submits (buggy retry loops, button mashing, spam clicks)
// are rejected in ~1ms instead of each paying an actor handshake + a full
// canister update call (seen 2026-08-29: ~22 concurrent retries fanned out
// across fresh containers, every one burning a cold start just to be told
// "wait 2 seconds"). Keyed on the raw credential rather than the resolved
// gameId (which isn't known until the API key is validated against the
// canister): one key/session maps to one game, so granularity matches.
// Per-container memory only -- a cold-start fan-out still reaches the
// canister, whose own cooldown remains authoritative. Same 400 status and
// exact error string as the canister path so clients can't tell which layer
// rejected them.
const writeGuardTimes = new Map();
const WRITE_GUARD_WINDOW_MS = 2000;
const WRITE_GUARD_MAX_ENTRIES = 5000;

// =====================================================
// Submit Ceilings (2026-10-14)
// =====================================================
// Context: 14 Oct a freshly registered clicker game submitted on every tap,
// ~3,000 submits from 3 players in four hours, each one a paid canister
// update. It sat just under the per-key tier limits (free: 50/min,
// 1000/hr in checkRateLimit), so nothing stopped it. The per-key limit
// bounds ONE key; it does nothing against many keys from one source
// (three free game slots per dashboard account), and there was no way to
// pause a single game short of revoking its key.
//
// Two ceilings, both per-container memory (max-instances=1 so that is the
// whole fleet), both only on POST /scores, both checked AFTER auth so the
// gameId is the canister-validated one, and both BEFORE any canister update:
//   1. Per-IP: SUBMIT_CAP_IP_PER_MIN submits/minute across all games from one
//      client IP. A phone can't exceed one every 2s (the write guard), so a
//      real device never gets near 60. Caps the many-keys-one-script case.
//   2. Pause list: PAUSED_GAMES env var, comma-separated game IDs. Submits
//      for a paused game get 503 + Retry-After without touching the canister.
//      Update with `gcloud run services update --update-env-vars` (new
//      revision in ~30s, no code deploy). Reads and sessions still work so a
//      paused game's leaderboards keep rendering.
//   3. Per-player (2026-10-17): SUBMIT_CAP_PLAYER_PER_HOUR submits/hour for
//      one (game, playerId). Both spam builds seen so far (23,045 and 3,726
//      submits from a single player ID in a week) sat under the IP cap
//      because one phone at ~17/min never reaches 60. One player ID doing
//      more than two submits a minute for an hour straight is a timer, not a
//      person. This is what makes the per-key tier limit safe to raise.
// Every reject logs evt=submit_cap_reject with scope/game/ip so the daily
// summaries show it. Limits are env vars so they tune without a deploy.
const SUBMIT_CAP_IP_PER_MIN = parseInt(process.env.SUBMIT_CAP_IP_PER_MIN || "60", 10);
const SUBMIT_CAP_PLAYER_PER_HOUR = parseInt(process.env.SUBMIT_CAP_PLAYER_PER_HOUR || "120", 10);
const PAUSED_GAMES = new Set((process.env.PAUSED_GAMES || "").split(",").map(s => s.trim()).filter(Boolean));
const submitIpWindows = new Map();       // ip -> { start: ms, count }
const submitPlayerWindows = new Map();   // "game:player" -> { start: ms, count }

// PENDING NICKNAMES (2026-10-19): some games ask for a name on first
// launch, before the player's first score. An external player only exists in
// the canister once a score creates it, so PUT /players/:id/nickname failed
// with a canister err for every brand-new player (~900 in 3 days, 100% fail
// rate). We now hold the name here and pass it as the nickname on that
// player's first submit, which is what names a player at creation.
// In-memory is fine for the same reason as the device-code store
// (max-instances=1). A restart in the gap just means the default name.
// Proper fix: make the canister's external changeNicknameAndGetProfile upsert.
const pendingNicknames = new Map();      // "game:player" -> { nickname, at }
const PENDING_NICK_TTL_MS = 24 * 3600 * 1000;
const PENDING_NICK_MAX_ENTRIES = 20000;
const PLAYER_NOT_FOUND_RE = /not found|does not exist|doesn't exist|no such|unknown (player|user)|not registered/i;
const SUBMIT_IP_MAX_ENTRIES = 10000;
const SUBMIT_PLAYER_MAX_ENTRIES = 20000;

// =====================================================
// Route Limits (SECURITY-AUDIT 2026-10-25)
// =====================================================
// Routes that reach the canister (or an outside service) with no API key
// used to have no limit at all: /auth/anonymous minted a session per call,
// and an anonymous session could then submit scores with neither the tier
// limit nor the per-player cap applying. Same for the device-code routes
// (unbounded memory + QR rendering per call) and /request-upgrade (an email
// per call). Env-tunable; every reject logs evt=route_limit_reject.
const LIMIT_ANON_AUTH_PER_IP_HOUR = envInt("LIMIT_ANON_AUTH_PER_IP_HOUR", 120);
const LIMIT_DEVICE_CODE_PER_IP_HOUR = envInt("LIMIT_DEVICE_CODE_PER_IP_HOUR", 30);
const LIMIT_DEVICE_APPROVE_PER_IP_HOUR = envInt("LIMIT_DEVICE_APPROVE_PER_IP_HOUR", 30);
const LIMIT_DEVICE_STATUS_PER_IP_MIN = envInt("LIMIT_DEVICE_STATUS_PER_IP_MIN", 60);
const LIMIT_UPGRADE_REQ_PER_IP_HOUR = envInt("LIMIT_UPGRADE_REQ_PER_IP_HOUR", 5);
// SECURITY (v1.11.3): Google/Apple sign-in had no route limit, so one valid ID
// token could be replayed to mint unlimited 30-day canister sessions. Two
// budgets: per client IP before any verification work, and per provider
// account (sub) after the token verifies. Covers dashboard sign-in and
// device-code approval.
const LIMIT_SOCIAL_AUTH_PER_IP_HOUR = envInt("LIMIT_SOCIAL_AUTH_PER_IP_HOUR", 30);
const LIMIT_SOCIAL_AUTH_PER_ACCOUNT_HOUR = envInt("LIMIT_SOCIAL_AUTH_PER_ACCOUNT_HOUR", 20);

// An empty client IP used to skip the limit entirely (routeLimit ignores empty
// keys). For auth routes, requests with no resolvable IP share one bucket.
function socialIpKey(ip) { return ip || "no-ip"; }

function socialAccountLimit(provider, sub) {
  if (!sub) return null;
  return routeLimit("social_acct", `${provider}:${sub}`, LIMIT_SOCIAL_AUTH_PER_ACCOUNT_HOUR, 3600000);
}
const LIMIT_SESSION_PLAY_PER_SESSION_HOUR = envInt("LIMIT_SESSION_PLAY_PER_SESSION_HOUR", 240);
const LIMIT_ACHIEVEMENT_CALLS_PER_PLAYER_HOUR = envInt("LIMIT_ACHIEVEMENT_CALLS_PER_PLAYER_HOUR", 120);
const MAX_ACHIEVEMENTS_PER_REQUEST = envInt("MAX_ACHIEVEMENTS_PER_REQUEST", 100);
const routeWindows = new Map();          // "scope:key" -> { start: ms, count }
const ROUTE_WINDOW_MAX_ENTRIES = 20000;

// Returns null when allowed, otherwise a ready-to-return 429. Missing key
// (no client IP) is allowed through rather than lumping everyone together.
function routeLimit(scope, key, max, windowMs) {
  if (!key || !(max > 0)) return null;
  const now = Date.now();
  const mapKey = `${scope}:${key}`;
  let w = routeWindows.get(mapKey);
  if (!w || (now - w.start) >= windowMs) {
    routeWindows.delete(mapKey);
    w = { start: now, count: 0 };
    // Windows differ per scope, so only sweep the clearly-dead (>1h) ones.
    boundedSet(routeWindows, mapKey, w, ROUTE_WINDOW_MAX_ENTRIES, (x) => (now - x.start) >= 3600000);
  }
  w.count += 1;
  if (w.count <= max) return null;
  const retry = Math.max(1, Math.ceil((windowMs - (now - w.start)) / 1000));
  if (w.count === max + 1) {
    logJson(`[CheddaAPI] route limit ${scope}`, { evt: "route_limit_reject", scope, key: cleanForLog(key), cap: max });
  }
  return error(429, "Too many requests. Please try again later.", { "Retry-After": String(retry) });
}

// Client IP for the per-IP limits.
// The client controls everything at the LEFT of X-Forwarded-For; each proxy
// appends the address it saw on the RIGHT. The old code used entry [0], so
// any caller could send their own XFF header and get a fresh "IP" per
// request, which defeated SUBMIT_CAP_IP_PER_MIN entirely.
// CLIENT_IP_HOPS = how many entries from the right the real client sits.
// Measured on the hosted service (2026-10-25): Firebase Hosting drops a
// client-sent XFF and forwards [client, google-hop], so CLIENT_IP_HOPS=2.
// Cloud Run hit directly (run.app) appends only the client, so a caller
// there can still choose the entry; block direct access if that matters.
// For your own deployment, CHECK before setting it: call
//   curl -H "X-Forwarded-For: 1.2.3.4" https://<your-api-host>/health
// and read clientIp.chain in the response. Your own IP should be in it; set
// CLIENT_IP_HOPS to its position counting from the right (last = 1).
// Unset (0) keeps the old leftmost behaviour and logs a warning at startup,
// because guessing wrong in the other direction would put every player
// behind the CDN on one shared IP and throttle all of them.
const CLIENT_IP_HOPS = envInt("CLIENT_IP_HOPS", 0);
if (!(CLIENT_IP_HOPS > 0)) {
  console.warn(JSON.stringify({ severity: "WARNING", evt: "client_ip_hops_unset",
    message: "CLIENT_IP_HOPS not set: per-IP limits use the spoofable leftmost X-Forwarded-For entry. See getClientIp." }));
}
function xffChain(headers) {
  const raw = headers["x-forwarded-for"] || headers["X-Forwarded-For"] || "";
  return String(raw).split(",").map(s => s.trim()).filter(Boolean);
}
function getClientIp(headers) {
  const parts = xffChain(headers);
  if (parts.length === 0) return "";
  const idx = CLIENT_IP_HOPS > 0 ? Math.max(0, parts.length - CLIENT_IP_HOPS) : 0;
  return cleanForLog(parts[idx]).slice(0, 64);
}

// Returns null when the submit may proceed, otherwise a ready-to-return
// response. Call with the validated gameId, the client IP and the playerId
// from the body (absent on session submits, which skip the player check).
function checkSubmitCeiling(gameId, clientIp, playerId = null) {
  if (gameId && PAUSED_GAMES.has(gameId)) {
    logJson(`[CheddaAPI] POST /scores paused game=${cleanForLog(gameId)}`, { evt: "submit_cap_reject", scope: "paused", game: cleanForLog(gameId), ...(clientIp ? { ip: clientIp } : {}) });
    return error(503, "Score submissions for this game are temporarily paused", { "Retry-After": "300" });
  }
  if (gameId && playerId && typeof playerId === "string" && SUBMIT_CAP_PLAYER_PER_HOUR > 0) {
    const now = Date.now();
    const key = `${gameId}:${playerId}`;
    let w = submitPlayerWindows.get(key);
    if (!w || (now - w.start) >= 3600000) {
      submitPlayerWindows.delete(key);
      w = { start: now, count: 0 };
      boundedSet(submitPlayerWindows, key, w, SUBMIT_PLAYER_MAX_ENTRIES, (x) => (now - x.start) >= 3600000);
    }
    w.count += 1;
    if (w.count > SUBMIT_CAP_PLAYER_PER_HOUR) {
      const retry = Math.max(1, Math.ceil((3600000 - (now - w.start)) / 1000));
      if (w.count === SUBMIT_CAP_PLAYER_PER_HOUR + 1) {
        logJson(`[CheddaAPI] POST /scores player-cap game=${cleanForLog(gameId)} player=${fp(playerId)}`, { evt: "submit_cap_reject", scope: "player", game: cleanForLog(gameId), player: fp(playerId), cap: SUBMIT_CAP_PLAYER_PER_HOUR, ...(clientIp ? { ip: clientIp } : {}) });
      }
      return error(429, "Too many score submissions for this player. Submit once per game over.", { "Retry-After": String(retry) });
    }
  }
  if (!clientIp || !(SUBMIT_CAP_IP_PER_MIN > 0)) return null;
  const now = Date.now();
  let w = submitIpWindows.get(clientIp);
  if (!w || (now - w.start) >= 60000) {
    submitIpWindows.delete(clientIp);
    w = { start: now, count: 0 };
    boundedSet(submitIpWindows, clientIp, w, SUBMIT_IP_MAX_ENTRIES, (x) => (now - x.start) >= 60000);
  }
  w.count += 1;
  if (w.count > SUBMIT_CAP_IP_PER_MIN) {
    const retry = Math.max(1, Math.ceil((60000 - (now - w.start)) / 1000));
    if (w.count === SUBMIT_CAP_IP_PER_MIN + 1) {
      // Log the first reject of the window only; a runaway client would
      // otherwise write a log line per request.
      logJson(`[CheddaAPI] POST /scores ip-cap game=${cleanForLog(gameId || "?")} ip=${clientIp}`, { evt: "submit_cap_reject", scope: "ip", game: cleanForLog(gameId || "?"), ip: clientIp, cap: SUBMIT_CAP_IP_PER_MIN });
    }
    return error(429, "Too many score submissions from this address", { "Retry-After": String(retry) });
  }
  return null;
}

async function getActor() {
  const now = Date.now();
  
  if (!cachedActor || (now - lastActorCreation) > ACTOR_TTL) {
    try {
      // Sign as the verifier identity so the canister's caller == VERIFIER gate
      // accepts these calls. On mainnet (icp-api.io) do NOT call fetchRootKey —
      // that's only for local replicas and would be a security hole in prod.
      cachedAgent = new HttpAgent({ host: ICP_HOST, identity: getVerifierIdentity() });
      cachedActor = Actor.createActor(idlFactory, {
        agent: cachedAgent,
        canisterId: CANISTER_ID,
      });
      lastActorCreation = now;
      // GET /health reports the principal this proxy signs as.
      logJson("[CheddaAPI] Actor created/refreshed", { evt: "actor_refresh" });
    } catch (err) {
      logError("[CheddaAPI] Failed to create actor", err, { evt: "actor_create_err" });
      throw new Error("Backend connection failed");
    }
  }
  
  return cachedActor;
}

// =====================================================
// Fan-Out Board Submit Conversion
// =====================================================
// FIX 2026-10-05: devs keep sending scoreboardId for the default period
// boards (all-time / weekly / daily, or any board flagged fan-out). The
// canister rejects that with "'X' is a fan-out board - submit without a
// scoreboardId". In the week to 4 Oct that was 175 of 242 failed submits
// across three games, and one of them never landed a single score. Rather than reject, treat a submit aimed at a fan-out
// board as the main submit it should have been: the score then fans out
// to every period board, which is what the dev wanted.
//
// Games that send one copy per board (e.g. all-time + weekly per run)
// would land 2-3 main submits per run and trip the canister's 2s
// cooldown on all but the first, swapping one error for another. So an
// identical (game, player, score, streak) arriving again inside a short
// window after a conversion is deduped: the first copy is written, the
// rest get an OK without a canister call. Both maps are per-container
// memory; a miss just costs one extra canister round-trip.
const fanOutBoards = new Map();      // "gameId:boardId" -> last confirmed ms
const FAN_OUT_TTL = 10 * 60 * 1000;
const fanOutDedupe = new Map();      // "gameId:who:score:streak" -> ms
const FAN_OUT_DEDUPE_WINDOW_MS = 10 * 1000;
const FAN_OUT_MAX_ENTRIES = 5000;

function isFanOutError(err) {
  return /fan-out board/i.test(String(err || ""));
}

function isKnownFanOut(gameId, boardId) {
  const t = fanOutBoards.get(`${gameId}:${boardId}`);
  return t !== undefined && (Date.now() - t) < FAN_OUT_TTL;
}

function rememberFanOut(gameId, boardId) {
  const now = Date.now();
  boundedSet(fanOutBoards, `${gameId}:${boardId}`, now, FAN_OUT_MAX_ENTRIES, (t) => (now - t) >= FAN_OUT_TTL);
}

// Returns true if this exact score was already converted within the window.
// Records the submit otherwise, so the first copy through is the one written.
function fanOutDuplicate(gameId, who, score, streak) {
  const key = `${gameId}:${who}:${score}:${streak}`;
  const now = Date.now();
  const last = fanOutDedupe.get(key);
  if (last !== undefined && (now - last) < FAN_OUT_DEDUPE_WINDOW_MS) return true;
  fanOutDedupe.delete(key);
  boundedSet(fanOutDedupe, key, now, FAN_OUT_MAX_ENTRIES, (t) => (now - t) >= FAN_OUT_DEDUPE_WINDOW_MS);
  return false;
}

// =====================================================
// Skip-Validation Session Short-Circuit
// =====================================================
// Games confirmed to have play-session time validation OFF (the canister
// returned a skip_validation_ token for them). While the flag is fresh, the
// proxy mints the placeholder token locally instead of paying a ~2s canister
// update call for a token that validates nothing. The TTL bounds staleness:
// if a dev turns validation ON, local minting stops within 5 minutes and the
// next start goes back through the canister.
const skipValidationGames = new Map(); // gameId -> last confirmed timestamp
const SKIP_VALIDATION_TTL = 5 * 60 * 1000;

// =====================================================
// OAuth Config Cache (per game)
// =====================================================
const oauthConfigCache = new Map();
const OAUTH_CACHE_TTL = 5 * 60 * 1000;

async function getGameOAuthConfig(actor, gameId) {
  const now = Date.now();
  const cached = oauthConfigCache.get(gameId);
  
  if (cached && (now - cached.timestamp) < OAUTH_CACHE_TTL) {
    return cached.config;
  }
  
  try {
    const result = await actor.getGameOAuthConfig(gameId);
    
    if (result && result[0]) {
      const config = result[0];
      oauthConfigCache.set(gameId, { config, timestamp: now });
      return config;
    }
    
    oauthConfigCache.set(gameId, { config: null, timestamp: now });
    return null;
  } catch (e) {
    logError("[OAuth] Failed to fetch config for game", e, { evt: "oauth_config_err", game: cleanForLog(gameId) });
    return null;
  }
}

// Game existence check with a short cache (positive and negative), so
// device-code mints for a mistyped game ID fail fast with a readable error
// instead of issuing a code that can never be approved. Seen 2026-10-04/05:
// a Godot 4.7 client requested codes for "my_game" (docs placeholder, wrong
// separator) and got a code back.
const gameExistsCache = new Map();
const GAME_EXISTS_TTL = 5 * 60 * 1000;

async function gameExists(actor, gameId) {
  const now = Date.now();
  const cached = gameExistsCache.get(gameId);
  if (cached && (now - cached.timestamp) < GAME_EXISTS_TTL) return cached.exists;
  try {
    const game = await actor.getGame(gameId);
    const exists = !!(game && game[0]);
    gameExistsCache.set(gameId, { exists, timestamp: now });
    return exists;
  } catch (e) {
    logError("[CheddaAPI] Game existence check failed", e, { evt: "game_exists_err", game: cleanForLog(gameId) });
    return true; // don't block a real game on a transient canister error
  }
}

// =====================================================
// Device Code Auth Store (RFC 8628)
// In-memory via memStore (single instance only; see note near the top)
// =====================================================

const DEVICE_CODE_TTL = 5 * 60 * 1000;       // 5 minutes
const DEVICE_CODE_POLL_INTERVAL = 5;           // seconds
const VERIFICATION_URL = process.env.DEVICE_AUTH_URL || "https://cheddaboards.com/link";

function generateDeviceCode() {
  return crypto.randomBytes(32).toString("hex");
}

// Canonical nickname rule (must match canister Players.validateNickname): 3-16 chars, [A-Za-z0-9_].
// Used to clean display names from OAuth providers (e.g. "John Smith") before
// sending to the canister, which now rejects invalid charsets on registration.
function sanitizeNickname(raw, fallback = "Player") {
  if (!raw) return fallback;
  let clean = String(raw).trim().replace(/\s+/g, "_").replace(/[^A-Za-z0-9_]/g, "");
  clean = clean.substring(0, 16);
  return clean.length >= 3 ? clean : fallback;
}

function generateUserCode() {
  // Human-friendly: CHEDDA-XXXXXX (no ambiguous chars I/O/0/1).
  // Uses crypto.randomInt for unbiased, cryptographically-secure selection.
  // 32^6 ≈ 1 billion combinations — three orders of magnitude harder to
  // brute-force than the previous 4-char version, while still typeable.
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "";
  for (let i = 0; i < 6; i++) {
    code += chars[crypto.randomInt(chars.length)];
  }
  return `CHEDDA-${code}`;
}

// Blob store helpers — keys prefixed to avoid collisions
// Device-code flow state — in-memory (see memstore.js; requires max-instances=1)
function getDeviceCodeStore() {
  return memStore;
}

// Index of live device codes so expired ones can be swept and the total
// capped. memStore only dropped an entry when someone read it after expiry,
// so codes nobody polled again stayed in memory forever.
const deviceCodeIndex = new Map(); // deviceCode -> { userCode, expiresAt }
const DEVICE_CODE_MAX_PENDING = envInt("DEVICE_CODE_MAX_PENDING", 5000);

function sweepDeviceCodes() {
  const now = Date.now();
  for (const [dc, meta] of deviceCodeIndex) {
    if (now > meta.expiresAt) {
      deviceCodeIndex.delete(dc);
      void deleteDeviceCode(dc, meta.userCode);
    }
  }
}

async function saveDeviceCode(deviceCode, entry) {
  deviceCodeIndex.set(deviceCode, { userCode: entry.userCode, expiresAt: entry.expiresAt });
  const store = getDeviceCodeStore();
  await store.setJSON(`dc:${deviceCode}`, entry);
  // Also save reverse lookup: user_code → device_code
  await store.setJSON(`uc:${entry.userCode}`, { deviceCode });
}

async function getDeviceCodeEntry(deviceCode) {
  const store = getDeviceCodeStore();
  try {
    const entry = await store.get(`dc:${deviceCode}`, { type: "json" });
    if (!entry) return null;
    // Check expiry
    if (Date.now() > entry.expiresAt) {
      await deleteDeviceCode(deviceCode, entry.userCode);
      return null;
    }
    return entry;
  } catch (e) {
    return null;
  }
}

async function getDeviceCodeByUserCode(userCode) {
  const store = getDeviceCodeStore();
  try {
    const lookup = await store.get(`uc:${userCode}`, { type: "json" });
    if (!lookup) return null;
    return lookup.deviceCode;
  } catch (e) {
    return null;
  }
}

async function updateDeviceCodeEntry(deviceCode, updates) {
  const store = getDeviceCodeStore();
  try {
    const entry = await store.get(`dc:${deviceCode}`, { type: "json" });
    if (!entry) return null;
    const updated = { ...entry, ...updates };
    await store.setJSON(`dc:${deviceCode}`, updated);
    return updated;
  } catch (e) {
    return null;
  }
}

async function deleteDeviceCode(deviceCode, userCode) {
  deviceCodeIndex.delete(deviceCode);
  const store = getDeviceCodeStore();
  try {
    await store.delete(`dc:${deviceCode}`);
    if (userCode) await store.delete(`uc:${userCode}`);
  } catch (e) {
    // ignore cleanup errors
  }
}

// =====================================================
// CORS
// =====================================================
// NOTE (Jul 2026): Origin allowlist disabled — CheddaBoards games run on
// arbitrary developer domains and CORS was blocking them. Security is
// handled by API key validation + canister-side authorizedProxies, not CORS.
// Planned: per-game origin registration in the developer dashboard, then
// an allowlist here built from it. No credentials ride on CORS (auth is by
// header, never cookies), so reflecting the origin exposes nothing extra.

function getResponseHeaders(origin) {
  return {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": origin || "*",
    "Vary": "Origin",
    "Access-Control-Allow-Headers": "Content-Type, X-API-Key, X-Game-ID, X-Session-Token, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "X-API-Version": API_VERSION,
  };
}

// =====================================================
// Response Helpers
// =====================================================
// FIX 2026-09-23 (timestamp precision): canister timestamps are Motoko Time
// (nanoseconds, ~1.7e18), well past Number.MAX_SAFE_INTEGER, so Number(bigint)
// rounded the last few digits. Direct canister reads return them exact, which
// meant the same entry's submittedAt differed depending on whether the SDK was
// served direct or via this proxy fallback. JSON.rawJSON (Node 21+) lets
// JSON.stringify emit the exact digits as a plain JSON number, so both paths
// are now identical. On older Node it falls back to the previous Number().
const HAS_RAW_JSON = typeof JSON.rawJSON === "function";
if (!HAS_RAW_JSON) {
  console.warn(JSON.stringify({ severity: "WARNING", message: "JSON.rawJSON unavailable (Node < 21): timestamps will be rounded" }));
}

function exactNat(v) {
  // Candid opt comes through as [] / [x]; mirror what Number() did with it.
  if (Array.isArray(v)) v = v.length ? v[0] : 0;
  if (!HAS_RAW_JSON || typeof v !== "bigint") return Number(v);
  return JSON.rawJSON(v.toString());
}

// FIX 2026-10-14 (CORS-CONTEXT-v1): the request's Origin used to live in a
// module-level `let _requestOrigin`, set at the top of handler(). That was
// fine on Netlify Functions (one request per invocation) but Cloud Run runs
// requests concurrently in one process. Request A sets the origin, awaits a
// ~1.4s canister call, request B (another game, or a native Godot client
// with no Origin header) overwrites it, and A's response goes out with B's
// origin in Access-Control-Allow-Origin. The browser then rejects a
// perfectly good 200 ("Origin X is not allowed by Access-Control-Allow-
// Origin. Status code: 200"), the SDK reports "Network error", and the
// score it just saved looks lost. Hit roughly 2 runs in 3 on a busy game
// page at ~1 req/s of mixed traffic. The origin now rides in AsyncLocalStorage,
// which is scoped to the async chain of the request that set it.
const requestContext = new AsyncLocalStorage();

function currentOrigin() {
  return requestContext.getStore()?.origin;
}

const respond = (statusCode, body, extraHeaders = {}) => ({
  statusCode,
  headers: { ...getResponseHeaders(currentOrigin()), ...extraHeaders },
  body: JSON.stringify(body),
});

const success = (data, extraHeaders = {}) => respond(200, { ok: true, data }, extraHeaders);

// FIX 2026-09-15 (CDN cached-404s): the hosted proxy runs behind a CDN
// (Firebase Hosting in front of Cloud Run). Error responses used to go out with
// no Cache-Control, so the edge heuristically cached them - a brand-new
// player's legitimate pre-first-submit profile 404 was then served from cache
// for MINUTES after the player existed (submits/renames fine - writes aren't
// cached - but the game kept seeing "new player" on the SAME profile URL).
// Direct run.app requests bypassed the CDN, which is why curl always looked
// fine while games broke. Negatives must never be cacheable, so every error
// response is no-store; extraHeaders can still override deliberately.
const error = (code, message, extraHeaders = {}) =>
  respond(code, { ok: false, error: message },
          { "Cache-Control": "no-store", ...extraHeaders });

// Dead-session canister errors must surface as 401, not 400: the SDK's
// session_expired self-heal only listens for 401. FIX 2026-08-21: "Invalid
// session: not found" (the post-cleanup tombstone of an expired session) was
// returned as 400, so clients with a dead stored session got a generic API
// error, kept looking logged in, and silently submitted nothing. Expired
// sessions are deleted server-side on first
// touch, so returning players see "not found" rather than "expired".
const sessionErrorStatus = (err) =>
  (typeof err === "string" &&
   (err.startsWith("Invalid session") ||
    (err.startsWith("Session expired") && !err.includes("Start a new game"))))
    ? 401 : 400;

// Log-hygiene: never print raw user emails in function logs (they persist in
// Netlify). "user@example.com" -> "us***@example.com".
const maskEmail = (email) => {
  if (typeof email !== "string") return "unknown";
  const at = email.indexOf("@");
  if (at <= 0) return "***";
  return email.slice(0, Math.min(2, at)) + "***" + email.slice(at);
};

// =====================================================
// JWT Utilities
// =====================================================

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) {
    str += '=';
  }
  return Buffer.from(str, 'base64').toString('utf8');
}

function decodeJwtPayload(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    return JSON.parse(base64UrlDecode(parts[1]));
  } catch (e) {
    return null;
  }
}

function decodeJwtHeader(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    return JSON.parse(base64UrlDecode(parts[0]));
  } catch (e) {
    return null;
  }
}

// =====================================================
// Google Token Verification (JWKS — cryptographic sig check)
// =====================================================

const GOOGLE_JWKS = createRemoteJWKSet(
  new URL("https://www.googleapis.com/oauth2/v3/certs")
);

async function verifyGoogleToken(idToken, allowedClientIds) {
  try {
    // Pre-check: decode unverified payload for early audience rejection
    const unverifiedPayload = decodeJwtPayload(idToken);
    if (!unverifiedPayload) {
      return { valid: false, error: "Invalid Google token format" };
    }

    if (allowedClientIds.length > 0 && !allowedClientIds.includes(unverifiedPayload.aud)) {
      console.error("[Google] Client ID mismatch. Got:", cleanForLog(unverifiedPayload.aud));
      return {
        valid: false,
        error: "Google client ID not registered for this game. Add your client ID in the CheddaBoards dashboard."
      };
    }

    // Full cryptographic verification against Google's JWKS
    const { payload } = await jwtVerify(idToken, GOOGLE_JWKS, {
      issuer: ["https://accounts.google.com", "accounts.google.com"],
      audience: allowedClientIds.length > 0 ? allowedClientIds : undefined,
    });

    if (!payload.sub) {
      return { valid: false, error: "Invalid Google token: missing subject" };
    }

    return {
      valid: true,
      user: {
        sub: payload.sub,
        email: typeof payload.email === "string" ? payload.email : null,
        emailVerified: payload.email_verified === true || payload.email_verified === "true",
        name: payload.name || (typeof payload.email === "string" ? payload.email.split("@")[0] : null) || "Player",
        picture: typeof payload.picture === "string" ? payload.picture : null,
      }
    };
  } catch (e) {
    console.error("[Google] Verification error:", e.message);
    return { valid: false, error: "Failed to verify Google token" };
  }
}

// =====================================================
// Apple Token Verification (JWKS — cryptographic sig check)
// =====================================================

const APPLE_JWKS = createRemoteJWKSet(
  new URL("https://appleid.apple.com/auth/keys")
);

async function verifyAppleToken(identityToken, allowedBundleId) {
  try {
    // Pre-check: decode unverified payload for early audience rejection
    const unverifiedPayload = decodeJwtPayload(identityToken);
    if (!unverifiedPayload) {
      return { valid: false, error: "Invalid Apple token format" };
    }

    if (allowedBundleId && unverifiedPayload.aud !== allowedBundleId) {
      console.error("[Apple] Bundle ID mismatch. Got:", cleanForLog(unverifiedPayload.aud), "Expected:", allowedBundleId);
      return {
        valid: false,
        error: "Apple bundle ID not registered for this game. Add your bundle ID in the CheddaBoards dashboard."
      };
    }

    // Full cryptographic verification against Apple's JWKS
    const { payload } = await jwtVerify(identityToken, APPLE_JWKS, {
      issuer: "https://appleid.apple.com",
      audience: allowedBundleId || undefined,
    });

    if (!payload.sub) {
      return { valid: false, error: "Invalid Apple token: missing subject" };
    }

    return {
      valid: true,
      user: {
        sub: payload.sub,
        email: typeof payload.email === "string" ? payload.email : null,
        emailVerified: payload.email_verified === "true" || payload.email_verified === true,
        isPrivateEmail: payload.is_private_email === "true" || payload.is_private_email === true,
      }
    };
  } catch (e) {
    console.error("[Apple] Verification error:", e.message);
    return { valid: false, error: "Failed to verify Apple token" };
  }
}

// =====================================================
// Auth Handlers
// =====================================================

async function handleGoogleAuth(actor, body, gameId) {
  const { idToken, nickname } = body;
  
  if (!idToken) {
    return error(400, "Missing required field: idToken");
  }
  
  if (!gameId) {
    return error(400, "Missing game ID. Include X-Game-ID header or gameId in body.");
  }
  
  // SECURITY 2026-10-25 (audit C1): sessions are keyed on email and not
  // scoped to a game, so accepting a developer-registered client ID let any
  // developer turn a Google login on their own site into a CheddaBoards
  // session for that user. Only CheddaBoards' own client IDs are accepted.
  let allowedClientIds = [];
  
  if (FALLBACK_GOOGLE_CLIENT_IDS.length > 0) {
    allowedClientIds = FALLBACK_GOOGLE_CLIENT_IDS;
  } else {
    return error(400, "Google Sign-In is not configured on this server (set GOOGLE_CLIENT_IDS).");
  }
  
  const verification = await verifyGoogleToken(idToken, allowedClientIds);
  
  if (!verification.valid) {
    return error(401, verification.error);
  }
  
  const googleUser = verification.user;
  const acctLimited = socialAccountLimit("google", googleUser.sub);
  if (acctLimited) return acctLimited;
  
  if (!googleUser.email) {
    return error(400, "Google account has no email associated");
  }
  // SECURITY-AUDIT 2026-10-25: accounts are keyed on email, so an unverified
  // email claim would let someone sign in as an address they don't own.
  if (!googleUser.emailVerified) {
    return error(401, "Google account email is not verified");
  }
  
  const userNickname = nickname || googleUser.name || googleUser.email.split("@")[0];
  
  try {
    const result = await actor.socialLoginAndGetProfile(
      googleUser.email,
      sanitizeNickname(userNickname),
      "google",
      gameId
    );
    
    if (result?.ok) {
      const data = result.ok;
      return success({
        sessionId: data.sessionId,
        nickname: data.nickname,
        isNewUser: data.isNewUser,
        message: data.message,
        email: googleUser.email,
        gameProfile: data.gameProfile ? {
          score: Number(data.gameProfile.total_score),
          streak: Number(data.gameProfile.best_streak),
          achievements: data.gameProfile.achievements,
          playCount: Number(data.gameProfile.play_count),
        } : null
      });
    }
    
    return error(400, result?.err || "Authentication failed");
  } catch (e) {
    console.error("[Auth] Google login error:", e);
    return error(500, "Failed to complete Google sign-in");
  }
}

async function handleAppleAuth(actor, body, gameId) {
  const { identityToken, authorizationCode, user, nickname } = body;
  
  if (!identityToken) {
    return error(400, "Missing required field: identityToken");
  }
  
  if (!gameId) {
    return error(400, "Missing game ID. Include X-Game-ID header or gameId in body.");
  }
  
  // SECURITY 2026-10-25 (audit C1): platform bundle ID only, see handleGoogleAuth.
  let allowedBundleId = null;
  
  if (FALLBACK_APPLE_BUNDLE_ID) {
    allowedBundleId = FALLBACK_APPLE_BUNDLE_ID;
  } else {
    return error(400, "Apple Sign-In is not configured on this server (set APPLE_BUNDLE_ID).");
  }
  
  const verification = await verifyAppleToken(identityToken, allowedBundleId);
  
  if (!verification.valid) {
    return error(401, verification.error);
  }
  
  const appleUser = verification.user;
  const acctLimited = socialAccountLimit("apple", appleUser.sub);
  if (acctLimited) return acctLimited;
  
  // SECURITY-AUDIT 2026-10-25: the email comes ONLY from the signed token.
  // This used to fall back to body.user.email, which the client controls, so
  // a valid Apple token with no email claim (app didn't request the email
  // scope) plus any address in the body logged in as that address. An
  // unverified token email is treated the same as none. Apple's first-login
  // `user` object is still used for the display name only.
  const email = (appleUser.email && appleUser.emailVerified)
    ? appleUser.email
    : `apple_${appleUser.sub}@privaterelay.appleid.com`;
  
  let userNickname = nickname;
  if (!userNickname && user?.name) {
    userNickname = user.name.firstName || user.name.givenName || "Player";
  }
  if (!userNickname) {
    userNickname = "Player";
  }
  
  try {
    const result = await actor.socialLoginAndGetProfile(
      email,
      sanitizeNickname(userNickname),
      "apple",
      gameId
    );
    
    if (result?.ok) {
      const data = result.ok;
      return success({
        sessionId: data.sessionId,
        nickname: data.nickname,
        isNewUser: data.isNewUser,
        message: data.message,
        gameProfile: data.gameProfile ? {
          score: Number(data.gameProfile.total_score),
          streak: Number(data.gameProfile.best_streak),
          achievements: data.gameProfile.achievements,
          playCount: Number(data.gameProfile.play_count),
        } : null
      });
    }
    
    return error(400, result?.err || "Authentication failed");
  } catch (e) {
    console.error("[Auth] Apple login error:", e);
    return error(500, "Failed to complete Apple sign-in");
  }
}

async function handleAnonymousAuth(actor, body, gameId) {
  const { deviceId, nickname } = body;
  
  if (!gameId) {
    return error(400, "Missing game ID. Include X-Game-ID header or gameId in body.");
  }
  
  // Fallbacks used only when the client doesn't provide its own identity
  // (the SDK always does — this guards against non-SDK callers). Both use
  // crypto.randomBytes for unguessable values, since a predictable fallback
  // device ID would let two clients accidentally collide into one profile.
  const finalDeviceId = deviceId || `anon_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`;
  const finalNickname = nickname || `Player_${crypto.randomBytes(2).toString("hex").toUpperCase()}`;
  
  try {
    const result = await actor.anonymousLoginAndGetProfile(
      finalDeviceId,
      sanitizeNickname(finalNickname),
      gameId
    );
    
    if (result?.ok) {
      const data = result.ok;
      return success({
        sessionId: data.sessionId,
        playerId: finalDeviceId,
        nickname: data.nickname,
        isNewUser: data.isNewUser,
        message: data.message,
        gameProfile: data.gameProfile ? {
          score: Number(data.gameProfile.total_score),
          streak: Number(data.gameProfile.best_streak),
          achievements: data.gameProfile.achievements,
          playCount: Number(data.gameProfile.play_count),
        } : null
      });
    }
    
    return error(400, result?.err || "Authentication failed");
  } catch (e) {
    console.error("[Auth] Anonymous login error:", e);
    return error(500, "Failed to complete anonymous sign-in");
  }
}

async function handleValidateSession(actor, sessionId) {
  if (!sessionId) {
    return error(401, "Missing session token");
  }
  
  try {
    const result = await actor.validateSession(sessionId);
    
    if (result?.ok) {
      return success({
        valid: true,
        email: result.ok.email,
        nickname: result.ok.nickname,
      });
    }
    
    return error(401, result?.err || "Invalid session");
  } catch (e) {
    console.error("[Auth] Session validation error:", e);
    return error(500, "Failed to validate session");
  }
}

async function handleLogout(actor, sessionId) {
  if (!sessionId) {
    return error(400, "Missing session token");
  }
  
  try {
    await actor.destroySession(sessionId);
    return success({ message: "Logged out successfully" });
  } catch (e) {
    return success({ message: "Logged out" });
  }
}

async function handleGetProfile(actor, sessionId, gameId) {
  if (!sessionId) {
    return error(401, "Missing session token");
  }
  
  try {
    const result = await actor.getMyProfileBySession(sessionId);
    
    if (result?.ok) {
      const profile = result.ok;
      
      let gameProfile = null;
      if (gameId) {
        for (const [gId, gp] of profile.gameProfiles) {
          if (gId === gameId) {
            gameProfile = {
              score: Number(gp.total_score),
              streak: Number(gp.best_streak),
              achievements: gp.achievements,
              playCount: Number(gp.play_count),
              lastPlayed: exactNat(gp.last_played),
            };
            break;
          }
        }
      }
      
      return success({
        nickname: profile.nickname,
        authType: profile.authType,
        created: exactNat(profile.created),
        lastUpdated: exactNat(profile.last_updated),
        gameProfile: gameProfile,
        totalGames: profile.gameProfiles.length,
      });
    }
    
    // Any canister error on this route means the session token is useless:
    // getMyProfileBySession can only fail with "Invalid session", "Session
    // expired", or "User not found" (account deleted while a device held a
    // session). All three must be 401 so the SDK clears its saved session
    // and returns to login — a 404 here reads as "new player, normal" and
    // the client keeps the dead token forever. (v2 of this fix pattern-
    // matched on "session" and missed "User not found".)
    return error(401, result?.err || "Session invalid");
  } catch (e) {
    console.error("[Auth] Get profile error:", e);
    return error(500, "Failed to fetch profile");
  }
}

// =====================================================
// PLAY SESSION HANDLERS (NEW v1.5.0)
// =====================================================

async function handleStartPlaySession(actor, apiKey, gameId, body, rateLimit) {
  const { playerId } = body;
  
  if (!playerId) {
    return error(400, "Missing required field: playerId");
  }
  
  if (typeof playerId !== "string" || playerId.length < 3 || playerId.length > 100) {
    return error(400, "playerId must be a string between 3-100 characters");
  }
  
  logJson(`[PlaySession] Starting session for game: ${cleanForLog(gameId)}, player: ${fp(playerId)}`, { evt: "session_start", auth: "api-key", game: cleanForLog(gameId), player: fp(playerId) });
  
  // Short-circuit: this game is known to have validation off, so the canister
  // would only hand back a skip_validation_ placeholder anyway. Mint it
  // locally and skip the ~2s update call. Clients treat the token as opaque.
  const skipFlag = skipValidationGames.get(gameId);
  if (skipFlag && (Date.now() - skipFlag) < SKIP_VALIDATION_TTL) {
    const localToken = `skip_validation_${gameId}_${Date.now()}`;
    logJson(`[PlaySession] Session started (local, validation off): ${localToken.substring(0, 12)}...`, { evt: "session_started", auth: "api-key", game: cleanForLog(gameId), mode: "skip_validation" });
    return success({ 
      ok: localToken,
      message: "Play session started"
    }, { "X-RateLimit-Remaining": String(rateLimit?.hour || 0) });
  }
  
  try {
    const result = await actor.startGameSessionByApiKey(apiKey, playerId, gameId);
    
    if (result?.ok) {
      logJson(`[PlaySession] Session started: ${result.ok.substring(0, 12)}...`, { evt: "session_started", auth: "api-key", game: cleanForLog(gameId) });
      if (result.ok.startsWith("skip_validation_")) {
        skipValidationGames.set(gameId, Date.now());
      }
      return success({ 
        ok: result.ok,
        message: "Play session started"
      }, { "X-RateLimit-Remaining": String(rateLimit?.hour || 0) });
    }
    
    if (result?.err) {
      logJson(`[PlaySession] Error: ${cleanForLog(result.err)}`, { evt: "session_start", auth: "api-key", game: cleanForLog(gameId), result: "err", err: cleanForLog(result.err) });
      return error(400, result.err);
    }
    
    return error(500, "Unexpected response from backend");
  } catch (e) {
    const detail = describeCanisterError(e);
    logError("[PlaySession] Start session error", e, { evt: "session_start_err", auth: "api-key", game: cleanForLog(gameId), detail });
    return error(500, `Failed to start play session: ${detail}`);
  }
}

async function handleStartPlaySessionBySession(actor, sessionId, gameId) {
  if (!sessionId) {
    return error(401, "Missing session token");
  }
  
  logJson(`[PlaySession] Starting session (OAuth) for game: ${cleanForLog(gameId)}`, { evt: "session_start", auth: "oauth", game: cleanForLog(gameId) });
  
  try {
    const result = await actor.startGameSessionBySession(sessionId, gameId);
    
    if (result?.ok) {
      logJson(`[PlaySession] Session started: ${result.ok.substring(0, 12)}...`, { evt: "session_started", auth: "oauth", game: cleanForLog(gameId) });
      return success({ 
        ok: result.ok,
        message: "Play session started"
      });
    }
    
    if (result?.err) {
      logJson(`[PlaySession] Error: ${cleanForLog(result.err)}`, { evt: "session_start", auth: "oauth", game: cleanForLog(gameId), result: "err", err: cleanForLog(result.err) });
      return error(400, result.err);
    }
    
    return error(500, "Unexpected response from backend");
  } catch (e) {
    const detail = describeCanisterError(e);
    logError("[PlaySession] Start session error", e, { evt: "session_start_err", auth: "oauth", game: cleanForLog(gameId), detail });
    return error(500, `Failed to start play session: ${detail}`);
  }
}

async function handleGetPlaySessionStatus(actor, sessionToken) {
  if (!sessionToken) {
    return error(400, "Missing session token parameter");
  }
  
  try {
    const result = await actor.getPlaySessionStatus(sessionToken);
    
    if (result?.ok) {
      const status = result.ok;
      return success({
        isValid: status.isValid,
        gameId: status.gameId,
        startedAt: exactNat(status.startedAt),
        expiresAt: exactNat(status.expiresAt),
        remainingSeconds: Number(status.remainingSeconds),
      });
    }
    
    if (result?.err) {
      return error(404, result.err);
    }
    
    return error(404, "Session not found");
  } catch (e) {
    console.error("[PlaySession] Get status error:", e);
    return error(500, "Failed to get play session status");
  }
}

// =====================================================
// END PLAY SESSION HANDLERS
// =====================================================

async function handleEndPlaySessionBySession(actor, sessionId, body) {
  if (!sessionId) {
    return error(401, "Missing session token");
  }
  
  const { playSessionToken } = body;
  if (!playSessionToken) {
    return error(400, "Missing required field: playSessionToken");
  }
  
  logJson(`[PlaySession] Ending session (OAuth): ${playSessionToken.substring(0, 12)}...`, { evt: "session_end", auth: "oauth" });
  
  if (playSessionToken.startsWith("skip_validation_")) {
    console.log("[PlaySession] Session ended (local, skip-validation token)");
    return success({ message: "Session ended" });
  }
  
  try {
    const result = await actor.cancelPlaySession(playSessionToken);
    
    if (result?.ok) {
      return success({ message: result.ok });
    }
    if (result?.err) {
      return error(404, result.err);
    }
    return error(500, "Unexpected response");
  } catch (e) {
    console.error("[PlaySession] End session error:", e);
    return error(500, "Failed to end play session");
  }
}

async function handleEndPlaySessionByApiKey(actor, body, rateLimit) {
  const { playSessionToken } = body;
  if (!playSessionToken) {
    return error(400, "Missing required field: playSessionToken");
  }
  
  logJson(`[PlaySession] Ending session (API key): ${playSessionToken.substring(0, 12)}...`, { evt: "session_end", auth: "api-key" });
  
  // Skip-validation tokens are self-describing placeholders: the canister
  // considered validation off when it issued one, so there is nothing to
  // cancel server-side. End locally, save the ~2s update call.
  if (playSessionToken.startsWith("skip_validation_")) {
    console.log("[PlaySession] Session ended (local, skip-validation token)");
    return success({ message: "Session ended" }, { "X-RateLimit-Remaining": String(rateLimit?.hour || 0) });
  }
  
  try {
    const result = await actor.cancelPlaySession(playSessionToken);
    
    if (result?.ok) {
      return success({ message: result.ok }, { "X-RateLimit-Remaining": String(rateLimit?.hour || 0) });
    }
    if (result?.err) {
      return error(404, result.err);
    }
    return error(500, "Unexpected response");
  } catch (e) {
    console.error("[PlaySession] End session error:", e);
    return error(500, "Failed to end play session");
  }
}

// =====================================================
// ACCOUNT MIGRATION HANDLERS
// =====================================================

async function handleMigrateAccount(actor, sessionId, body) {
  if (!sessionId) {
    return error(401, "Missing session token");
  }
  
  const { deviceId } = body;
  if (!deviceId) {
    return error(400, "Missing required field: deviceId");
  }
  
  logJson("[Migration] Migrating anonymous device to authenticated account", { evt: "migration", device: fp(deviceId) });
  
  try {
    const result = await actor.migrateAnonymousAccount(sessionId, deviceId);
    
    if (result?.ok) {
      const data = result.ok;
      return success({
        message: data.message,
        migratedGames: Number(data.migratedGames),
        migratedScoreboards: Number(data.migratedScoreboards),
      });
    }
    if (result?.err) {
      return error(400, result.err);
    }
    return error(500, "Unexpected response");
  } catch (e) {
    logError("[Migration] Account migration error", e, { evt: "migration_err" });
    return error(500, "Failed to migrate account. Please retry.");
  }
}

// =====================================================
// DEVICE CODE AUTH HANDLERS (NEW v1.7.0)
// =====================================================

async function handleDeviceCodeRequest(gameId, requestedNickname) {
  if (!gameId) {
    return error(400, "Missing game ID. Include X-Game-ID header or gameId in body.");
  }
  
  sweepDeviceCodes();
  if (deviceCodeIndex.size >= DEVICE_CODE_MAX_PENDING) {
    logJson("[DeviceCode] pending cap reached", { evt: "device_code_cap", pending: deviceCodeIndex.size });
    return error(503, "Too many pending device authorizations. Try again shortly.", { "Retry-After": "60" });
  }

  // Generate unique codes
  const deviceCode = generateDeviceCode();
  let userCode = generateUserCode();
  
  // Check for collision (32^6 space, unlikely but possible)
  let attempts = 0;
  try {
    let existing = await getDeviceCodeByUserCode(userCode);
    while (existing && attempts < 10) {
      userCode = generateUserCode();
      existing = await getDeviceCodeByUserCode(userCode);
      attempts++;
    }
    if (existing) {
      return error(503, "Too many pending device authorizations. Try again shortly.");
    }
  } catch (e) {
    console.error("[DeviceCode] Blob collision check failed:", e.message);
    // Continue anyway — collision is unlikely
  }
  
  const now = Date.now();
  const entry = {
    userCode,
    gameId,
    status: "pending",
    session: null,
    // Player's in-game (anon) nickname, seeded by the SDK so a NEW account
    // created at approval is born with the name they chose in-game.
    nickname: requestedNickname ? sanitizeNickname(requestedNickname, null) : null,
    createdAt: now,
    expiresAt: now + DEVICE_CODE_TTL,
  };
  
  try {
    await saveDeviceCode(deviceCode, entry);
  } catch (e) {
    console.error("[DeviceCode] Failed to save device code to blob store:", e.message, e.stack);
    return error(500, "Failed to create device code");
  }
  
  logJson(`[DeviceCode] Created for game ${gameId}: ${userCode}`, { evt: "device_code_created", game: cleanForLog(gameId), code: userCode });

  const verificationUrlComplete = `${VERIFICATION_URL}?code=${encodeURIComponent(userCode)}`;

  let qrDataUrl = null;
  try {
    qrDataUrl = await QRCode.toDataURL(verificationUrlComplete, { width: 300, margin: 2 });
  } catch (e) {
    console.error("[DeviceCode] QR generation failed:", e.message);
    // Non-fatal — client falls back to displaying the raw code
  }

  return success({
    device_code: deviceCode,
    user_code: userCode,
    verification_url: VERIFICATION_URL,
    verification_url_complete: verificationUrlComplete,
    qr_data_url: qrDataUrl,
    expires_in: Math.floor(DEVICE_CODE_TTL / 1000),
    interval: DEVICE_CODE_POLL_INTERVAL,
  });
}

async function handleDeviceCodeToken(body) {
  const { device_code } = body;
  
  if (!device_code) {
    return error(400, "Missing required field: device_code");
  }
  
  const entry = await getDeviceCodeEntry(device_code);
  
  if (!entry) {
    return error(404, "Invalid or expired device code");
  }
  
  // Check expiry
  if (Date.now() > entry.expiresAt) {
    await deleteDeviceCode(device_code, entry.userCode);
    return respond(410, { ok: false, error: "expired_token", error_description: "The device code has expired. Please request a new one." },
                   { "Cache-Control": "no-store" });
  }
  
  // Still waiting for user
  if (entry.status === "pending") {
    return respond(428, { ok: false, error: "authorization_pending", error_description: "The user has not yet completed authorization." },
                   { "Cache-Control": "no-store" });
  }
  
  // User completed login — return session data
  if ((entry.status === "approved" || entry.status === "consumed") && entry.session) {
    const session = entry.session;
    
    if (entry.status === "approved") {
      // Mark consumed but keep the entry so re-polls work
      await updateDeviceCodeEntry(device_code, { status: "consumed" });
      logJson(`[DeviceCode] Token exchanged for ${entry.userCode}`, { evt: "device_code_exchanged", code: entry.userCode });
    } else {
      logJson(`[DeviceCode] Token re-fetched for ${entry.userCode} (already consumed)`, { evt: "device_code_refetched", code: entry.userCode });
    }
    
    return success({
      sessionId: session.sessionId,
      nickname: session.nickname,
      isNewUser: session.isNewUser,
      message: session.message,
      email: session.email,
      provider: session.provider || "google",
      gameProfile: session.gameProfile || null,
    });
  }
  
  return error(500, "Unexpected device code state");
}

async function handleDeviceCodeApprove(actor, body) {
  const { user_code, idToken, identityToken, provider, nickname } = body;
  
  if (!user_code) {
    return error(400, "Missing required field: user_code");
  }
  
  // Normalize user code (uppercase, trim)
  const normalizedCode = user_code.trim().toUpperCase();
  
  const deviceCode = await getDeviceCodeByUserCode(normalizedCode);
  if (!deviceCode) {
    return error(404, "Invalid or expired user code. Please check and try again.");
  }
  
  const entry = await getDeviceCodeEntry(deviceCode);
  if (!entry) {
    return error(404, "Device code expired. The game will need to request a new code.");
  }
  
  if (Date.now() > entry.expiresAt) {
    await deleteDeviceCode(deviceCode, normalizedCode);
    return error(410, "Code expired. The game will need to request a new code.");
  }
  
  if (entry.status !== "pending") {
    return error(409, "This code has already been used.");
  }
  
  const gameId = entry.gameId;
  
  // Determine provider and verify token
  const authProvider = provider || (identityToken ? "apple" : "google");
  
  if (authProvider === "google") {
    if (!idToken) {
      return error(400, "Missing required field: idToken (Google ID token)");
    }
    
    // The token comes from the CheddaBoards verification page,
    // so we validate against OUR web client ID, not the game's.
    // The game's per-game client IDs are for direct native sign-in only.
    let allowedClientIds = [];
    
    if (DEVICE_AUTH_GOOGLE_CLIENT_ID) {
      allowedClientIds = [DEVICE_AUTH_GOOGLE_CLIENT_ID];
    } else if (FALLBACK_GOOGLE_CLIENT_IDS.length > 0) {
      // Fallback: accept any of our own client IDs
      allowedClientIds = FALLBACK_GOOGLE_CLIENT_IDS;
    }
    
    // SECURITY 2026-10-25 (audit C1): the game's own client IDs are no
    // longer merged in here; only CheddaBoards' link-page IDs are accepted.
    
    if (allowedClientIds.length === 0) {
      return error(400, "Google Sign-In not configured. Set DEVICE_AUTH_GOOGLE_CLIENT_ID.");
    }
    
    const verification = await verifyGoogleToken(idToken, allowedClientIds);
    if (!verification.valid) {
      return error(401, verification.error);
    }
    
    const googleUser = verification.user;
    const acctLimited = socialAccountLimit("google", googleUser.sub);
    if (acctLimited) return acctLimited;
    if (!googleUser.email) {
      return error(400, "Google account has no email associated");
    }
    if (!googleUser.emailVerified) {
      return error(401, "Google account email is not verified");
    }
    
    const userNickname = nickname || entry.nickname || googleUser.name || googleUser.email.split("@")[0];
    
    try {
      const result = await actor.socialLoginAndGetProfile(
        googleUser.email,
        sanitizeNickname(userNickname),
        "google",
        gameId
      );
      
      if (result?.ok) {
        const data = result.ok;
        await updateDeviceCodeEntry(deviceCode, {
          status: "approved",
          session: {
            sessionId: data.sessionId,
            nickname: data.nickname,
            isNewUser: data.isNewUser,
            message: data.message,
            email: googleUser.email,
            provider: authProvider,
            gameProfile: data.gameProfile ? {
              score: Number(data.gameProfile.total_score),
              streak: Number(data.gameProfile.best_streak),
              achievements: data.gameProfile.achievements,
              playCount: Number(data.gameProfile.play_count),
            } : null,
          },
        });
        
        logJson(`[DeviceCode] Approved ${normalizedCode} via Google (${maskEmail(googleUser.email)})`, { evt: "device_code_approved", provider: "google", code: normalizedCode });
      return success({ message: "Authorization complete. You can return to your game.", nickname: data.nickname });
      }
      
      return error(400, result?.err || "Authentication failed");
    } catch (e) {
      console.error("[DeviceCode] Google auth error:", e);
      return error(500, "Failed to complete Google sign-in");
    }
    
  } else if (authProvider === "apple") {
    const appleToken = identityToken || idToken;
    if (!appleToken) {
      return error(400, "Missing required field: identityToken (Apple identity token)");
    }
    
    // Same as Google: validate against OUR bundle ID first,
    // fall back to game's if needed
    let allowedBundleId = null;
    
    if (DEVICE_AUTH_APPLE_BUNDLE_ID) {
      allowedBundleId = DEVICE_AUTH_APPLE_BUNDLE_ID;
    } else if (FALLBACK_APPLE_BUNDLE_ID) {
      allowedBundleId = FALLBACK_APPLE_BUNDLE_ID;
    }
    // SECURITY 2026-10-25 (audit C1): no per-game bundle ID fallback.
    
    if (!allowedBundleId) {
      return error(400, "Apple Sign-In not configured. Set DEVICE_AUTH_APPLE_BUNDLE_ID.");
    }
    
    const verification = await verifyAppleToken(appleToken, allowedBundleId);
    if (!verification.valid) {
      return error(401, verification.error);
    }
    
    const appleUser = verification.user;
    const acctLimited = socialAccountLimit("apple", appleUser.sub);
    if (acctLimited) return acctLimited;
    const email = (appleUser.email && appleUser.emailVerified)
      ? appleUser.email
      : `apple_${appleUser.sub}@privaterelay.appleid.com`;
    const userNickname = nickname || entry.nickname || "Player";
    
    try {
      const result = await actor.socialLoginAndGetProfile(
        email,
        sanitizeNickname(userNickname),
        "apple",
        gameId
      );
      
      if (result?.ok) {
        const data = result.ok;
        await updateDeviceCodeEntry(deviceCode, {
          status: "approved",
          session: {
            sessionId: data.sessionId,
            nickname: data.nickname,
            isNewUser: data.isNewUser,
            message: data.message,
            email: email,
            provider: authProvider,
            gameProfile: data.gameProfile ? {
              score: Number(data.gameProfile.total_score),
              streak: Number(data.gameProfile.best_streak),
              achievements: data.gameProfile.achievements,
              playCount: Number(data.gameProfile.play_count),
            } : null,
          },
        });
        
        logJson(`[DeviceCode] Approved ${normalizedCode} via Apple (${maskEmail(email)})`, { evt: "device_code_approved", provider: "apple", code: normalizedCode });
      return success({ message: "Authorization complete. You can return to your game.", nickname: data.nickname }); 
         }
      
      return error(400, result?.err || "Authentication failed");
    } catch (e) {
      console.error("[DeviceCode] Apple auth error:", e);
      return error(500, "Failed to complete Apple sign-in");
    }
    
  } else {
    return error(400, "Invalid provider. Must be 'google' or 'apple'.");
  }
}

async function handleDeviceCodeStatus(userCode) {
  if (!userCode) {
    return error(400, "Missing user code");
  }
  
  const normalizedCode = userCode.trim().toUpperCase();
  const deviceCode = await getDeviceCodeByUserCode(normalizedCode);
  
  if (!deviceCode) {
    return error(404, "Invalid or expired code");
  }
  
  const entry = await getDeviceCodeEntry(deviceCode);
  if (!entry) {
    return error(404, "Code expired");
  }
  
  const now = Date.now();
  if (now > entry.expiresAt) {
    return error(410, "Code expired");
  }
  
  return success({
    valid: true,
    gameId: entry.gameId,
    status: entry.status,
    expires_in: Math.floor((entry.expiresAt - now) / 1000),
  });
}

// =====================================================
// Session-based game operations
// =====================================================

async function handleSessionSubmitScore(actor, sessionId, gameId, body) {
  const { score, streak, rounds, playSessionToken, scoreboardId } = body;
  
  if (!sessionId) return error(401, "Missing session token");
  if (typeof score !== "number" || score < 0) return error(400, "score must be a non-negative number");
  if (scoreboardId !== undefined && (typeof scoreboardId !== "string" || !scoreboardId)) {
    return error(400, "scoreboardId, if provided, must be a non-empty string");
  }
  
  logJson(`[CheddaAPI] POST /scores (session) game=${cleanForLog(gameId)} board=${cleanForLog(scoreboardId || "main")}`, { evt: "submit", auth: "session", game: cleanForLog(gameId), board: cleanForLog(scoreboardId || "main") });
  
  try {
    // Targeted submit: write to ONE named board only (no fan-out, no
    // aggregate). FIX 2026-07-10: this handler previously ignored
    // scoreboardId entirely - session (logged-in) category-board
    // submissions were silently landing on the MAIN board and sharing
    // its per-(user, game) cooldown key, so multi-board game-overs
    // 400'd with "wait 2 seconds" for logged-in players only. Mirrors
    // handleExternalSubmitScore; submitScoreToBoard keys its cooldown
    // per-(user, game, board).
    let fanOut = false; // scoreboardId named a fan-out board: converted to a main submit
    if (scoreboardId && !isKnownFanOut(gameId, scoreboardId)) {
      const boardResult = await actor.submitScoreToBoard(
        "session", sessionId, gameId, scoreboardId,
        Math.floor(score), Math.floor(streak || 0),
        [],
        playSessionToken ? [playSessionToken] : []
      );
      if (boardResult?.ok) {
        logJson(`[CheddaAPI] POST /scores (session) game=${cleanForLog(gameId)} board=${cleanForLog(scoreboardId)} result=ok`, { evt: "submit", auth: "session", game: cleanForLog(gameId), board: cleanForLog(scoreboardId), result: "ok" });
        return success({ message: boardResult.ok, scoreboardId });
      }
      if (boardResult?.err && !isFanOutError(boardResult.err)) {
        logJson(`[CheddaAPI] POST /scores (session) game=${cleanForLog(gameId)} board=${cleanForLog(scoreboardId)} result=err "${cleanForLog(boardResult.err)}"`, { evt: "submit", auth: "session", game: cleanForLog(gameId), board: cleanForLog(scoreboardId), result: "err", err: cleanForLog(boardResult.err) });
        return error(sessionErrorStatus(boardResult.err), boardResult.err);
      }
      if (!boardResult?.err) return success({ message: "Score submitted", scoreboardId });
      rememberFanOut(gameId, scoreboardId);
    }
    if (scoreboardId) {
      fanOut = true;
      logJson(`[CheddaAPI] POST /scores (session) game=${cleanForLog(gameId)} board=${cleanForLog(scoreboardId)} fan-out board, converted to main submit`, { evt: "fanout_convert", auth: "session", game: cleanForLog(gameId), board: cleanForLog(scoreboardId) });
      if (fanOutDuplicate(gameId, sessionId, Math.floor(score), Math.floor(streak || 0))) {
        logJson(`[CheddaAPI] POST /scores (session) game=${cleanForLog(gameId)} board=main result=ok (deduped fan-out copy)`, { evt: "submit", auth: "session", game: cleanForLog(gameId), board: "main", result: "ok", deduped: true });
        return success({ message: "Score already recorded for this run (fan-out board)", scoreboardId, fanOut: true });
      }
    }
    
    const result = await actor.submitScore(
      "session", sessionId, gameId,
      Math.floor(score), Math.floor(streak || 0),
      rounds ? [Math.floor(rounds)] : [], 
      [],
      playSessionToken ? [playSessionToken] : []
    );
    
    if (result?.ok) {
      logJson(`[CheddaAPI] POST /scores (session) game=${cleanForLog(gameId)} board=main result=ok`, { evt: "submit", auth: "session", game: cleanForLog(gameId), board: "main", result: "ok" });
      return success(fanOut ? { message: result.ok, scoreboardId, fanOut: true } : { message: result.ok });
    }
    if (result?.err) {
      logJson(`[CheddaAPI] POST /scores (session) game=${cleanForLog(gameId)} board=main result=err "${cleanForLog(result.err)}"`, { evt: "submit", auth: "session", game: cleanForLog(gameId), board: "main", result: "err", err: cleanForLog(result.err) });
      return error(sessionErrorStatus(result.err), result.err);
    }
    return success({ message: "Score submitted" });
  } catch (e) {
    logError("[Session] Submit score error", e, { evt: "submit_err", auth: "session" });
    return error(500, "Failed to submit score");
  }
}

// FIX 2026-08-27 (achievements latency): both achievement handlers used to
// loop `await actor.unlockAchievement(...)` per ID - each is an IC update
// call (~1s consensus), so a ~32-achievement batch ran 26-30s and hit
// Netlify's 30s function cap (502s seen in testing 15 Aug, confirmed in logs
// 26 Aug). Now one unlockAchievementBatch update call does the whole batch
// in a single consensus round. The per-ID loop survives only as a fallback
// so this proxy can deploy safely against a canister that predates the
// method (deploy order: canister first, fresh did.js into _lib, then proxy).
// NOTE: _lib/cheddaboards_v2_backend.did.js MUST contain
// unlockAchievementBatch or the batch call throws and every request takes
// the slow fallback - watch for the fallback warn line after deploying.
// Shape check before anything reaches the canister. The array used to go
// through unbounded and untyped.
function achievementIdsError(ids) {
  if (!Array.isArray(ids) || ids.length === 0) return "Missing required field: achievementId or achievementIds";
  if (ids.length > MAX_ACHIEVEMENTS_PER_REQUEST) return `Too many achievements in one request (max ${MAX_ACHIEVEMENTS_PER_REQUEST})`;
  if (!ids.every(id => typeof id === "string" && id.length > 0 && id.length <= 64)) {
    return "achievementIds must be non-empty strings of at most 64 characters";
  }
  return null;
}

async function unlockAchievementsBatched(actor, userIdType, userId, gameId, idsToUnlock) {
  try {
    const result = await actor.unlockAchievementBatch(userIdType, userId, gameId, idsToUnlock);
    if (result?.err !== undefined) return { batchError: result.err };
    const ok = result.ok;
    const results = [
      ...ok.unlocked.map(id => ({ achievementId: id, success: true, message: "unlocked" })),
      ...ok.alreadyUnlocked.map(id => ({ achievementId: id, success: true, message: "Achievement already unlocked." })),
      ...ok.failed.map(([id, err]) => ({ achievementId: id, success: false, error: err })),
    ];
    return { results, successCount: ok.unlocked.length + ok.alreadyUnlocked.length };
  } catch (e) {
    // Batch method missing from the live canister/IDL -> legacy per-ID loop
    console.warn("[Achievements] Batch call failed, falling back to per-ID loop:", e.message);
    const results = [];
    for (const achId of idsToUnlock) {
      try {
        const result = await actor.unlockAchievement(userIdType, userId, gameId, achId);
        if (result?.err !== undefined) {
          results.push({ achievementId: achId, success: false, error: result.err });
        } else {
          results.push({ achievementId: achId, success: true, message: result?.ok || "unlocked" });
        }
      } catch (err) {
        results.push({ achievementId: achId, success: false, error: err.message });
      }
    }
    return { results, successCount: results.filter(r => r.success).length };
  }
}

async function handleSessionUnlockAchievement(actor, sessionId, gameId, body) {
  // Supports both single (achievementId) and batch (achievementIds) -
  // mirrors the external/API-key handler. Previously this only read the
  // singular field, so every session-authenticated batch got a 400 and
  // logged-in players' achievements never persisted (the SDK's flush is
  // fire-and-forget, so it failed silently). Same class of bug as the
  // old handleSessionSubmitScore scoreboardId issue.
  const { achievementId, achievementIds } = body;
  
  if (!sessionId) return error(401, "Missing session token");
  
  const idsToUnlock = achievementIds || (achievementId ? [achievementId] : []);
  const badIds = achievementIdsError(idsToUnlock);
  if (badIds) return error(400, badIds);
  const achLimited = routeLimit("ach", `${gameId}:${fp(sessionId)}`, LIMIT_ACHIEVEMENT_CALLS_PER_PLAYER_HOUR, 3600000);
  if (achLimited) return achLimited;
  
  try {
    const outcome = await unlockAchievementsBatched(actor, "session", sessionId, gameId, idsToUnlock);
    if (outcome.batchError !== undefined) {
      // Whole-batch rejection (dead session, game not found, ...). Dead
      // sessions map to 401 so the SDK's session_expired self-heal fires,
      // same as the score-submit routes (SESSION-401-v1 fix).
      return error(sessionErrorStatus(outcome.batchError), outcome.batchError);
    }
    const { results, successCount } = outcome;
    return success({
      message: `${successCount}/${idsToUnlock.length} achievements unlocked`,
      synced: successCount,
      unlocked: successCount,
      total: idsToUnlock.length,
      results
    });
  } catch (e) {
    console.error("[Session] Achievement error:", e);
    return error(500, "Failed to unlock achievements");
  }
}

async function handleSessionChangeNickname(actor, sessionId, gameId, body) {
  const { nickname } = body;
  
  if (!sessionId) return error(401, "Missing session token");
  if (!nickname || nickname.length < 3) {
    return error(400, "Nickname must be at least 3 characters");
  }
  if (nickname.length > 16) {
    return error(400, "Nickname must be 16 characters or less");
  }
  if (!/^[A-Za-z0-9_]+$/.test(nickname)) {
    return error(400, "Nickname can only contain letters, numbers, and underscores");
  }
  
  try {
    const result = await actor.changeNicknameAndGetProfile("session", sessionId, nickname, gameId);
    
    if (result?.ok) {
      // The canister may auto-suffix if name was taken (e.g., "Chedz" -> "Chedz_1")
      const finalNickname = result.ok.nickname;
      const wasAutoSuffixed = finalNickname !== nickname;
      
      if (wasAutoSuffixed) {
        console.log(`[Session] Nickname '${nickname}' was taken, auto-suffixed to '${finalNickname}'`);
      }
      
      return success({
        message: result.ok.message,
        nickname: finalNickname,
        requestedNickname: nickname,
        wasAutoSuffixed: wasAutoSuffixed,
        gameProfile: result.ok.gameProfile ? {
          score: Number(result.ok.gameProfile.total_score),
          streak: Number(result.ok.gameProfile.best_streak),
        } : null
      });
    }
    if (result?.err) return error(400, result.err);
    return error(500, "Unexpected response");
  } catch (e) {
    console.error("[Session] Nickname change error:", e);
    return error(500, "Failed to change nickname");
  }
}

/**
 * Check if a nickname is available
 * GET /nickname/check?name=xxx
 */
async function handleNicknameCheck(actor, nickname, gameId) {
  if (!nickname) {
    return error(400, "Missing 'name' query parameter");
  }
  
  const trimmed = nickname.trim();
  
  // Validation
  if (trimmed.length < 3 || trimmed.length > 16) {
    return success({ 
      available: false, 
      reason: "length",
      message: "Name must be 3-16 characters" 
    });
  }
  
  if (!/^[a-zA-Z0-9_]+$/.test(trimmed)) {
    return success({ 
      available: false, 
      reason: "characters",
      message: "Only letters, numbers, and underscores allowed" 
    });
  }
  
  try {
    // Use canister method to check all players
    const available = await actor.isNicknameAvailable(trimmed, gameId);
    
    return success({
      available: available,
      reason: available ? null : "taken",
      message: available ? "Name is available!" : "Name is already taken"
    });
    
  } catch (e) {
    console.error("[Nickname] Check error:", e);
    
    // Fallback: check via leaderboard if canister method fails
    try {
      const scoreboards = ["weekly", "alltime"];
      
      for (const board of scoreboards) {
        try {
          const result = await actor.getScoreboard(gameId, board, 500);
          if (result?.ok) {
            const entries = result.ok.entries || result.ok;
            for (const entry of entries) {
              if (entry.nickname && entry.nickname.toLowerCase() === trimmed.toLowerCase()) {
                return success({
                  available: false,
                  reason: "taken",
                  message: "Name is already taken"
                });
              }
            }
          }
        } catch (e2) {
          // Continue checking other scoreboards
        }
      }
      
      return success({
        available: true,
        reason: null,
        message: "Name appears to be available"
      });
    } catch (e3) {
      // Don't block user on check failures - let them try
      return success({ 
        available: true, 
        reason: "unknown",
        message: "Could not verify availability"
      });
    }
  }
}

// =====================================================
// SCOREBOARD HANDLERS
// =====================================================

async function handleListScoreboards(actor, gameId) {
  try {
    const scoreboards = await actor.getScoreboardsForGame(gameId);
    
    return success({
      gameId: gameId,
      scoreboards: scoreboards.map(sb => ({
        scoreboardId: sb.scoreboardId,
        name: sb.name,
        description: sb.description,
        period: sb.period,
        sortBy: sb.sortBy,
        maxEntries: Number(sb.maxEntries),
        entryCount: Number(sb.entryCount),
        lastReset: exactNat(sb.lastReset),
        isActive: sb.isActive,
      }))
    }, CACHE_BOARD_READ);
  } catch (e) {
    console.error("[Scoreboard] List error:", e);
    return error(500, "Failed to fetch scoreboards");
  }
}

async function handleGetScoreboard(actor, gameId, scoreboardId, limit) {
  try {
    const result = await actor.getScoreboard(gameId, scoreboardId, limit);
    
    if (result?.ok) {
      const config = result.ok.config;
      const entries = result.ok.entries;
      
      return success({
        scoreboardId: scoreboardId,
        config: {
          name: config.name,
          description: config.description,
          period: config.period,
          sortBy: config.sortBy,
          lastReset: exactNat(config.lastReset),
        },
        entries: entries.map(e => ({
          rank: Number(e.rank),
          nickname: e.nickname,
          score: Number(e.score),
          streak: Number(e.streak),
          authType: e.authType,
          submittedAt: exactNat(e.submittedAt),
        })),
        totalEntries: entries.length,
      }, CACHE_BOARD_READ);
    }
    
    if (result?.err) {
      return error(404, result.err);
    }
    
    return error(404, "Scoreboard not found");
  } catch (e) {
    console.error("[Scoreboard] Get error:", e);
    return error(500, "Failed to fetch scoreboard");
  }
}

async function handleGetPlayerRank(actor, gameId, scoreboardId, sessionId) {
  try {
    const sessionResult = await actor.validateSession(sessionId);
    if (!sessionResult?.ok) {
      return error(401, "Invalid session");
    }

    // Fetch the board so we know its period + sortBy (and, for period boards,
    // its entries). getScoreboard also gives us a natural 404 if it's missing.
    const result = await actor.getScoreboard(gameId, scoreboardId, 1000);
    if (!result?.ok) {
      return error(404, result?.err || "Scoreboard not found");
    }

    const entries = result.ok.entries;
    const config = result.ok.config;

    // ── All-time: rank from the all-time BOARD (not player profiles) ────────
    // Previously this used getPlayerRank (profile scan), whose population differs
    // from the board: it double-counts users present in both usersByEmail and
    // usersByPrincipal, and includes un-merged anonymous (ext:) profiles — so its
    // rank/total disagreed with the visible board (e.g. "57 of 84" vs "40 of 68").
    // The all-time board holds up to 1000 entries (effectively uncapped here), so
    // ranking against it covers every player AND matches the board the user sees.
    if (config.period === "allTime") {
      // v-fix: pass the REQUESTED board id through. This was hardcoded
      // "all-time" from when the all-time board was the only allTime-
      // period board - every targeted custom board, and even one named
      // "all-time-board", queried a
      // board that doesn't exist, so rank always came back empty while
      // the player sat on the visible board.
      const rankResult = await actor.getPlayerScoreboardRank(
        gameId, scoreboardId, "session", sessionId
      );
      console.log(`[Rank] allTime lookup board='${scoreboardId}' found=${!!(rankResult && rankResult[0])}`);
      const r = rankResult && rankResult[0]; // candid opt -> [] | [record]

      if (r) {
        return success({
          found: true,
          rank: Number(r.rank),
          score: Number(r.score),
          streak: Number(r.streak),
          totalPlayers: Number(r.totalPlayers),
        });
      }

      // null => player has no entry on the all-time board yet.
      return success({
        found: false,
        message: "Player has no entry on the all-time board yet",
        totalPlayers: entries.length,
      });
    }

    // ── Weekly / daily / custom: buffer-based, matched by nickname ──────────
    const sessionNickname = sessionResult.ok.nickname;

    // Try matching by session nickname first
    let playerEntry = entries.find(e => e.nickname === sessionNickname);

    // Fallback: try profile nickname (may differ from session after rename)
    if (!playerEntry) {
      try {
        const profileResult = await actor.getMyProfileBySession(sessionId);
        if (profileResult?.ok && profileResult.ok.nickname !== sessionNickname) {
          const profileNickname = profileResult.ok.nickname;
          playerEntry = entries.find(e => e.nickname === profileNickname);
          if (playerEntry) {
            console.log(`[Rank] Found by profile nickname '${profileNickname}' (session had '${sessionNickname}')`);
          }
        }
      } catch (e) {
        // Profile fetch failed, continue with session result
      }
    }

    if (playerEntry) {
      return success({
        found: true,
        rank: Number(playerEntry.rank),
        score: Number(playerEntry.score),
        streak: Number(playerEntry.streak),
        totalPlayers: entries.length,
      });
    }

    // Debug: log mismatch when player not found
    const entryNicks = entries.map(e => e.nickname);
    console.log(`[Rank] Player not found. Session nick: '${sessionNickname}', Board entries: [${entryNicks.join(', ')}]`);

    return success({
      found: false,
      message: "Player not on this scoreboard yet",
      totalPlayers: entries.length,
    });
  } catch (e) {
    console.error("[Scoreboard] Get rank error:", e);
    return error(500, "Failed to fetch player rank");
  }
}

// FIX 2026-09-23 (missing route): the Unity SDK's GetPlayerRank() calls
// GET /players/:playerId/rank, which never existed here, so every call 404'd
// (seen repeatedly in the logs). Anonymous
// API-key players had no rank endpoint at all. Ranks against an allTime-period
// board (default "all-time", override with ?board=), matching what the player
// sees. ?sort= is accepted for SDK compatibility but boards carry their own
// sortBy, so it's ignored. Response shape matches the SDK's player_rank parser.
async function handleExternalPlayerRank(actor, gameId, playerId, query, rateLimit) {
  const headers = { "Cache-Control": "no-store", "X-RateLimit-Remaining": String(rateLimit?.hour || 0) };
  const boardId = query.board || "all-time";
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(boardId) || !playerId) {
    return error(400, "Invalid board or player ID");
  }
  try {
    const result = await actor.getScoreboard(gameId, boardId, 1000);
    if (!result?.ok) {
      return error(404, result?.err || "Scoreboard not found");
    }
    const entries = result.ok.entries;

    // Primary: canister-side lookup by external player ID.
    let r = null;
    try {
      const rankResult = await actor.getPlayerScoreboardRank(gameId, boardId, "external", playerId);
      r = rankResult && rankResult[0]; // candid opt -> [] | [record]
    } catch (e) {
      logError("[Rank] external lookup failed, falling back to nickname match", e, { evt: "rank_err", game: cleanForLog(gameId), board: cleanForLog(boardId) });
    }
    if (r) {
      return success({
        found: true,
        rank: Number(r.rank),
        score: Number(r.score),
        streak: Number(r.streak),
        totalPlayers: Number(r.totalPlayers),
      }, headers);
    }

    // Fallback: resolve the player's nickname and find it on the board
    // (same approach the session handler uses for period boards).
    try {
      const profile = await actor.getUserProfile("external", playerId);
      const nickname = profile?.ok?.nickname;
      const entry = nickname ? entries.find(e => e.nickname === nickname) : null;
      if (entry) {
        return success({
          found: true,
          rank: Number(entry.rank),
          score: Number(entry.score),
          streak: Number(entry.streak),
          totalPlayers: entries.length,
        }, headers);
      }
    } catch (e) {
      // No profile yet (player hasn't submitted) - fall through to not-found.
    }

    return success({
      found: false,
      message: "Player not on this scoreboard yet",
      totalPlayers: entries.length,
    }, headers);
  } catch (e) {
    logError("[Rank] external rank error", e, { evt: "rank_err", game: cleanForLog(gameId), board: cleanForLog(boardId) });
    return error(500, "Failed to fetch player rank");
  }
}

async function handleCreateScoreboard(actor, sessionId, gameId, body) {
  const { scoreboardId, name, description, period, sortBy, maxEntries, targeted, intervalDays } = body;
  
  if (!sessionId) return error(401, "Missing session token");
  if (!scoreboardId) return error(400, "Missing required field: scoreboardId");
  if (!name) return error(400, "Missing required field: name");
  
  const validPeriods = ["allTime", "daily", "weekly", "monthly", "custom"];
  if (period && !validPeriods.includes(period)) {
    return error(400, `Invalid period. Must be one of: ${validPeriods.join(", ")}`);
  }
  
  const validSortBy = ["score", "streak"];
  if (sortBy && !validSortBy.includes(sortBy)) {
    return error(400, `Invalid sortBy. Must be one of: ${validSortBy.join(", ")}`);
  }
  
  if (targeted !== undefined && typeof targeted !== "boolean") {
    return error(400, "targeted, if provided, must be a boolean");
  }
  if (intervalDays !== undefined && intervalDays !== null &&
      (typeof intervalDays !== "number" || !Number.isInteger(intervalDays) || intervalDays < 0)) {
    return error(400, "intervalDays, if provided, must be a non-negative integer");
  }
  
  try {
    const result = await actor.createScoreboardBySession(
      sessionId,
      gameId,
      scoreboardId,
      name,
      description || "",
      period || "allTime",
      sortBy || "score",
      maxEntries ? [maxEntries] : [],
      targeted === true,
      (intervalDays !== undefined && intervalDays !== null) ? [Math.floor(intervalDays)] : []
    );
    
    if (result?.ok) return success({ message: result.ok, scoreboardId });
    if (result?.err) return error(400, result.err);
    return error(500, "Unexpected response");
  } catch (e) {
    console.error("[Scoreboard] Create error:", e);
    return error(500, "Failed to create scoreboard");
  }
}

async function handleResetScoreboard(actor, sessionId, gameId, scoreboardId) {
  if (!sessionId) return error(401, "Missing session token");
  
  try {
    const result = await actor.resetScoreboardBySession(sessionId, gameId, scoreboardId);
    
    if (result?.ok) return success({ message: result.ok });
    if (result?.err) return error(400, result.err);
    return error(500, "Unexpected response");
  } catch (e) {
    console.error("[Scoreboard] Reset error:", e);
    return error(500, "Failed to reset scoreboard");
  }
}

async function handleDeleteScoreboard(actor, sessionId, gameId, scoreboardId) {
  if (!sessionId) return error(401, "Missing session token");
  
  try {
    const result = await actor.deleteScoreboardBySession(sessionId, gameId, scoreboardId);
    
    if (result?.ok) return success({ message: result.ok });
    if (result?.err) return error(400, result.err);
    return error(500, "Unexpected response");
  } catch (e) {
    console.error("[Scoreboard] Delete error:", e);
    return error(500, "Failed to delete scoreboard");
  }
}

// =====================================================
// SCOREBOARD ARCHIVE HANDLERS (NEW v1.4.0)
// =====================================================

async function handleListArchives(actor, gameId, scoreboardId, query) {
  try {
    let archives;
    
    if (query.after && query.before) {
      archives = await actor.getArchivesInRange(
        gameId,
        scoreboardId,
        BigInt(query.after),
        BigInt(query.before)
      );
    } else {
      archives = await actor.getScoreboardArchives(gameId, scoreboardId);
    }
    
    return success({
      gameId: gameId,
      scoreboardId: scoreboardId,
      archives: archives.map(archive => ({
        archiveId: archive.archiveId,
        scoreboardId: archive.scoreboardId,
        periodStart: exactNat(archive.periodStart),
        periodEnd: exactNat(archive.periodEnd),
        entryCount: Number(archive.entryCount),
        topPlayer: archive.topPlayer[0] || null,
        topScore: Number(archive.topScore),
      }))
    });
  } catch (e) {
    console.error("[Archive] List error:", e);
    return error(500, "Failed to fetch archives");
  }
}

async function handleGetLastArchive(actor, gameId, scoreboardId, limit) {
  try {
    const result = await actor.getLastArchivedScoreboard(gameId, scoreboardId, limit);
    
    if (result?.err) {
      return error(404, result.err);
    }
    
    const archive = result.ok;
    
    return success({
      archiveId: archive.archiveId,
      config: {
        name: archive.config.name,
        period: archive.config.period,
        sortBy: archive.config.sortBy,
        periodStart: exactNat(archive.config.periodStart),
        periodEnd: exactNat(archive.config.periodEnd),
      },
      entries: archive.entries.map(e => ({
        rank: Number(e.rank),
        nickname: e.nickname,
        score: Number(e.score),
        streak: Number(e.streak),
        authType: e.authType,
        submittedAt: exactNat(e.submittedAt),
      })),
      totalEntries: archive.entries.length,
    });
  } catch (e) {
    console.error("[Archive] Get last error:", e);
    return error(500, "Failed to fetch last archive");
  }
}

async function handleGetArchive(actor, archiveId, limit) {
  try {
    const result = await actor.getArchivedScoreboard(archiveId, limit);
    
    if (result?.err) {
      return error(404, result.err);
    }
    
    const archive = result.ok;
    
    return success({
      archiveId: archiveId,
      config: {
        name: archive.config.name,
        period: archive.config.period,
        sortBy: archive.config.sortBy,
        periodStart: exactNat(archive.config.periodStart),
        periodEnd: exactNat(archive.config.periodEnd),
      },
      entries: archive.entries.map(e => ({
        rank: Number(e.rank),
        nickname: e.nickname,
        score: Number(e.score),
        streak: Number(e.streak),
        authType: e.authType,
        submittedAt: exactNat(e.submittedAt),
      })),
      totalEntries: archive.entries.length,
    });
  } catch (e) {
    console.error("[Archive] Get error:", e);
    return error(500, "Failed to fetch archive");
  }
}

async function handleGetArchiveStats(actor, gameId) {
  try {
    const stats = await actor.getArchiveStats(gameId);
    
    return success({
      gameId: gameId,
      totalArchives: Number(stats.totalArchives),
      byScoreboard: stats.byScoreboard.map(([scoreboardId, count]) => ({
        scoreboardId,
        count: Number(count),
      })),
    });
  } catch (e) {
    console.error("[Archive] Stats error:", e);
    return error(500, "Failed to fetch archive stats");
  }
}

// =====================================================
// API Key Handling
// =====================================================

// SECURITY (2026-10-04): the "demo_" key path is gone. It accepted any key
// starting with demo_ as valid for whatever game the X-Game-ID header named,
// without asking the canister. Every key is now validated by the canister.
//
// TIER LIMIT COUNTS WRITES ONLY (2026-10-17): checkRateLimit used to count
// every key-authenticated request, reads and play-session calls included.
// A free-tier game making ~3.3 requests per game-over (session start,
// submit, session end, board reads) hit the 1000/hr ceiling at ~300
// games/hr, and the request that got the 429 was usually the score itself
// (361 of 387 tier rejects in the 10-17 Oct logs landed on POST /scores).
// Reads are cached and sessions are cheap; the paid thing is a canister
// update. So only canister writes (POST /scores, POST /achievements,
// PUT /players/:id/nickname) consume the per-key budget now. Other
// requests still report X-RateLimit-Remaining, they just don't spend it.
//
// FREE TIER RAISED (2026-10-17): 1000/hr was a 2x margin over the biggest
// live game, which makes it a player cap, not an abuse ceiling. Free is
// pitched as no player limits, so these numbers only exist to stop a
// runaway script; a real game should never see them. Runaway single
// clients are caught by the per-player ceiling in checkSubmitCeiling.
const rateLimitMap = new Map();

function getRateLimitForTier(tier) {
  switch (tier) {
    case "enterprise": return { perHour: Infinity, perMinute: Infinity };
    case "pro": return { perHour: 50000, perMinute: 500 };
    case "free": return { perHour: 5000, perMinute: 100 };
    default: return { perHour: 100, perMinute: 10 };
  }
}

// consume=false reports the remaining budget without spending any of it,
// and never rejects: reads and session calls go through regardless.
function checkRateLimit(apiKey, tier, consume = true) {
  const limits = getRateLimitForTier(tier);
  const now = Date.now();
  const minuteAgo = now - 60000;
  const hourAgo = now - 3600000;
  
  let entry = rateLimitMap.get(apiKey);
  if (!entry) {
    entry = { requests: [] };
    rateLimitMap.set(apiKey, entry);
  }
  
  entry.requests = entry.requests.filter(t => t > hourAgo);
  
  const requestsLastMinute = entry.requests.filter(t => t > minuteAgo).length;
  const requestsLastHour = entry.requests.length;

  if (!consume) {
    return { allowed: true, remaining: {
      minute: Math.max(limits.perMinute - requestsLastMinute, 0),
      hour: Math.max(limits.perHour - requestsLastHour, 0),
    }};
  }

  if (requestsLastMinute >= limits.perMinute) {
    return { allowed: false, error: "Rate limit exceeded (per minute)", retryAfter: 60 };
  }

  if (requestsLastHour >= limits.perHour) {
    return { allowed: false, error: "Rate limit exceeded (per hour)", retryAfter: 3600 };
  }

  entry.requests.push(now);

  return { allowed: true, remaining: { minute: limits.perMinute - requestsLastMinute - 1, hour: limits.perHour - requestsLastHour - 1 }};
}

// Which API-key requests spend the tier budget: the ones that end in a
// canister update. Everything else (reads, play sessions, health) is free.
function isTierCountedRequest(method, pathParts) {
  if (method === "POST" && (pathParts[0] === "scores" || pathParts[0] === "achievements")) return true;
  if (method === "PUT" && pathParts[0] === "players" && pathParts[2] === "nickname") return true;
  return false;
}

async function validateApiKeyAsync(apiKey, actor, gameIdHeader = null, countsAgainstLimit = true) {
  if (!apiKey) return { valid: false, error: "Missing API key" };

  try {
    const result = await actor.validateApiKeyQuery(apiKey);

    if (result && result[0]) {
      const keyData = result[0];
      if (!keyData.isActive) return { valid: false, error: "API key has been revoked" };

      const rateCheck = checkRateLimit(apiKey, keyData.tier, countsAgainstLimit);
      if (!rateCheck.allowed) return { valid: false, error: rateCheck.error, retryAfter: rateCheck.retryAfter };
      
      return { valid: true, gameId: keyData.gameId, tier: keyData.tier, rateLimit: rateCheck.remaining };
    }
    
    return { valid: false, error: "Invalid API key" };
  } catch (e) {
    logError("[CheddaAPI] Key validation error", e, { evt: "key_validation_err" });
    return { valid: false, error: "Failed to validate API key" };
  }
}

async function handleExternalSubmitScore(actor, apiKey, gameId, body, rateLimit) {
  const { playerId, score, streak, rounds, playSessionToken, scoreboardId } = body;
  let { nickname } = body;
  
  if (!playerId) return error(400, "Missing required field: playerId");
  if (typeof playerId !== "string" || playerId.length < 1 || playerId.length > 100) {
    return error(400, "playerId must be a string between 1-100 characters");
  }

  // Apply a nickname the player chose before their first score (see pendingNicknames).
  const pendKey = `${gameId}:${playerId}`;
  const pend = pendingNicknames.get(pendKey);
  let usedPending = false;
  if (pend) {
    if (Date.now() - pend.at >= PENDING_NICK_TTL_MS) {
      pendingNicknames.delete(pendKey);
    } else if (!nickname) {
      nickname = pend.nickname;
      usedPending = true;
    }
  }
  if (typeof score !== "number" || score < 0 || !Number.isFinite(score)) {
    return error(400, "score must be a non-negative number");
  }
  if (scoreboardId !== undefined && (typeof scoreboardId !== "string" || !scoreboardId)) {
    return error(400, "scoreboardId, if provided, must be a non-empty string");
  }
  
  logJson(`[CheddaAPI] POST /scores (api-key) game=${cleanForLog(gameId)} board=${cleanForLog(scoreboardId || "main")} player=${fp(playerId)}`, { evt: "submit", auth: "api-key", game: cleanForLog(gameId), board: cleanForLog(scoreboardId || "main"), player: fp(playerId) });
  
  try {
    // Targeted submit: write to ONE named board only (no fan-out, no aggregate).
    let fanOut = false; // scoreboardId named a fan-out board: converted to a main submit
    if (scoreboardId && !isKnownFanOut(gameId, scoreboardId)) {
      const result = await actor.submitScoreToBoard(
        "external", playerId, gameId, scoreboardId,
        Math.floor(score), Math.floor(streak || 0),
        nickname ? [nickname] : [],
        playSessionToken ? [playSessionToken] : []
      );
      if (result?.ok) {
        if (pend) pendingNicknames.delete(pendKey);
        if (usedPending) logJson(`[CheddaAPI] pending nickname applied game=${cleanForLog(gameId)} player=${fp(playerId)}`, { evt: "nickname_pending_applied", game: cleanForLog(gameId) });
        logJson(`[CheddaAPI] POST /scores (api-key) game=${cleanForLog(gameId)} board=${cleanForLog(scoreboardId)} player=${fp(playerId)} result=ok`, { evt: "submit", auth: "api-key", game: cleanForLog(gameId), board: cleanForLog(scoreboardId), player: fp(playerId), result: "ok" });
        return success({ message: result.ok, scoreboardId }, { "X-RateLimit-Remaining": String(rateLimit?.hour || 0) });
      }
      if (result?.err && !isFanOutError(result.err)) {
        logJson(`[CheddaAPI] POST /scores (api-key) game=${cleanForLog(gameId)} board=${cleanForLog(scoreboardId)} player=${fp(playerId)} result=err "${cleanForLog(result.err)}"`, { evt: "submit", auth: "api-key", game: cleanForLog(gameId), board: cleanForLog(scoreboardId), player: fp(playerId), result: "err", err: cleanForLog(result.err) });
        invalidateSkipCacheIfRejected(gameId, playSessionToken, result.err);
        return error(400, result.err);
      }
      if (!result?.err) return success({ message: "Score submitted", scoreboardId });
      rememberFanOut(gameId, scoreboardId);
    }
    if (scoreboardId) {
      fanOut = true;
      logJson(`[CheddaAPI] POST /scores (api-key) game=${cleanForLog(gameId)} board=${cleanForLog(scoreboardId)} player=${fp(playerId)} fan-out board, converted to main submit`, { evt: "fanout_convert", auth: "api-key", game: cleanForLog(gameId), board: cleanForLog(scoreboardId), player: fp(playerId) });
      if (fanOutDuplicate(gameId, playerId, Math.floor(score), Math.floor(streak || 0))) {
        logJson(`[CheddaAPI] POST /scores (api-key) game=${cleanForLog(gameId)} board=main player=${fp(playerId)} result=ok (deduped fan-out copy)`, { evt: "submit", auth: "api-key", game: cleanForLog(gameId), board: "main", player: fp(playerId), result: "ok", deduped: true });
        return success({ message: "Score already recorded for this run (fan-out board)", scoreboardId, fanOut: true }, { "X-RateLimit-Remaining": String(rateLimit?.hour || 0) });
      }
    }

    const result = await actor.submitScore(
      "external", playerId, gameId,
      Math.floor(score), Math.floor(streak || 0),
      rounds ? [Math.floor(rounds)] : [],
      nickname ? [nickname] : [],
      playSessionToken ? [playSessionToken] : []
    );
    
    if (result?.ok) {
      if (pend) pendingNicknames.delete(pendKey);
      if (usedPending) logJson(`[CheddaAPI] pending nickname applied game=${cleanForLog(gameId)} player=${fp(playerId)}`, { evt: "nickname_pending_applied", game: cleanForLog(gameId) });
      logJson(`[CheddaAPI] POST /scores (api-key) game=${cleanForLog(gameId)} board=main player=${fp(playerId)} result=ok`, { evt: "submit", auth: "api-key", game: cleanForLog(gameId), board: "main", player: fp(playerId), result: "ok" });
      return success(fanOut ? { message: result.ok, scoreboardId, fanOut: true } : { message: result.ok }, { "X-RateLimit-Remaining": String(rateLimit?.hour || 0) });
    }
    if (result?.err) {
      logJson(`[CheddaAPI] POST /scores (api-key) game=${cleanForLog(gameId)} board=main player=${fp(playerId)} result=err "${cleanForLog(result.err)}"`, { evt: "submit", auth: "api-key", game: cleanForLog(gameId), board: "main", player: fp(playerId), result: "err", err: cleanForLog(result.err) });
      invalidateSkipCacheIfRejected(gameId, playSessionToken, result.err);
      return error(400, result.err);
    }
    return success({ message: "Score submitted" });
  } catch (e) {
    logError("[CheddaAPI] Submit score error", e, { evt: "submit_err", auth: "api-key" });
    return error(500, "Failed to submit score");
  }
}

async function handleExternalChangeNickname(actor, gameId, playerId, body, rateLimit) {
  const { nickname } = body;
  
  if (!nickname || nickname.length < 3) {
    return error(400, "Nickname must be at least 3 characters");
  }
  if (nickname.length > 16) {
    return error(400, "Nickname must be 16 characters or less");
  }
  if (!/^[A-Za-z0-9_]+$/.test(nickname)) {
    return error(400, "Nickname can only contain letters, numbers, and underscores");
  }
  
  try {
    const result = await actor.changeNicknameAndGetProfile(
      "external",
      playerId,
      nickname,
      gameId
    );
    
    if (result?.ok) {
      pendingNicknames.delete(`${gameId}:${playerId}`);
      return success({
        message: result.ok.message,
        nickname: result.ok.nickname,
        gameProfile: result.ok.gameProfile ? {
          score: Number(result.ok.gameProfile.total_score),
          streak: Number(result.ok.gameProfile.best_streak),
        } : null
      }, { "X-RateLimit-Remaining": String(rateLimit?.hour || 0) });
    }
    if (result?.err) {
      const errStr = String(result.err);
      if (PLAYER_NOT_FOUND_RE.test(errStr)) {
        // Player not created yet (no score so far): hold the name for their first submit.
        const nowPend = Date.now();
        boundedSet(pendingNicknames, `${gameId}:${playerId}`, { nickname, at: nowPend }, PENDING_NICK_MAX_ENTRIES,
          (p) => (nowPend - p.at) >= PENDING_NICK_TTL_MS);
        logJson(`[CheddaAPI] nickname queued until first score game=${cleanForLog(gameId)} player=${fp(playerId)} err="${cleanForLog(errStr)}"`,
          { evt: "nickname_pending", game: cleanForLog(gameId), player: fp(playerId), err: cleanForLog(errStr) });
        return success({
          message: "Nickname saved. It will appear on the leaderboard with your first score.",
          nickname,
          pending: true,
          gameProfile: null,
        }, { "X-RateLimit-Remaining": String(rateLimit?.hour || 0) });
      }
      logJson(`[CheddaAPI] nickname reject game=${cleanForLog(gameId)} player=${fp(playerId)} err="${cleanForLog(errStr)}"`,
        { evt: "nickname_reject", game: cleanForLog(gameId), player: fp(playerId), err: cleanForLog(errStr) });
      return error(400, result.err);
    }
    return error(500, "Unexpected response");
  } catch (e) {
    console.error("[API] External nickname change error:", e);
    return error(500, "Failed to change nickname");
  }
}

async function handleGetLeaderboard(actor, gameId, query) {
  const sortBy = query.sort === "streak" ? { streak: null } : { score: null };
  const limit = parseLimit(query);
  
  try {
    const results = await actor.getLeaderboard(gameId, sortBy, limit);
    
    const leaderboard = results.map((entry, index) => ({
      rank: index + 1,
      nickname: entry[0],
      score: Number(entry[1]),
      streak: Number(entry[2]),
      authType: entry[3],
    }));
    
    return success({ leaderboard, total: leaderboard.length }, CACHE_LEADERBOARD);
  } catch (e) {
    logError("[CheddaAPI] Leaderboard error", e, { evt: "leaderboard_err" });
    return error(500, "Failed to fetch leaderboard");
  }
}

async function handleGetGameInfo(actor, gameId) {
  try {
    const game = await actor.getGame(gameId);
    
    if (game && game[0]) {
      const g = game[0];
      
      const oauthConfig = await getGameOAuthConfig(actor, gameId);
      
      let scoreboards = [];
      try {
        const sbList = await actor.getScoreboardsForGame(gameId);
        scoreboards = sbList.map(sb => ({
          scoreboardId: sb.scoreboardId,
          name: sb.name,
          period: sb.period,
        }));
      } catch (e) {
        // Scoreboards not available, that's ok
      }
      
      return success({
        gameId: g.gameId,
        name: g.name,
        description: g.description,
        totalPlayers: Number(g.totalPlayers),
        totalPlays: Number(g.totalPlays),
        isActive: g.isActive,
        timeValidationEnabled: g.timeValidationEnabled || false,
        nativeAuth: {
          googleEnabled: oauthConfig?.googleClientIds?.length > 0 || FALLBACK_GOOGLE_CLIENT_IDS.length > 0,
          appleEnabled: !!oauthConfig?.appleBundleId || !!FALLBACK_APPLE_BUNDLE_ID,
        },
        scoreboards: scoreboards,
      });
    }
    return error(404, "Game not found");
  } catch (e) {
    return error(500, "Failed to fetch game info");
  }
}

// =====================================================
// Main Handler
// =====================================================
// =====================================================
// DEV BOARD MODERATION HANDLERS (dashboard)
// =====================================================
// All auth happens in the canister (session -> owner check); these are
// thin passthroughs that map canister errors onto HTTP status codes.

// FIX 2026-10-05: in one week two live games were calling routes that don't
// exist (/leaderboards/<game>, /boards/<board>/entries) and reading the bare
// 404 as "empty board", so their players saw blank leaderboards for days.
// A guessed route now points at the real one in the error body.
function unknownEndpointMessage(method, path) {
  const p = String(path || "").toLowerCase();
  const looksLikeRead = /leaderboard|board|entries|rank|top|scores\//.test(p);
  const looksLikeSubmit = method === "POST" && /submit|score/.test(p);
  let hint = "";
  if (looksLikeSubmit) {
    hint = " To submit a score use POST /scores with X-API-Key and X-Game-ID headers and a JSON body {playerId, score}, adding scoreboardId only for a custom board.";
  } else if (looksLikeRead) {
    hint = " To read a board use GET /games/{gameId}/scoreboards/{scoreboardId}?limit=10 (scoreboardId is all-time, weekly, daily or your custom board ID) with your X-API-Key header.";
  }
  return `Unknown endpoint: ${method} ${path}.${hint} Full reference: https://docs.cheddaboards.com (or GET /docs).`;
}

function moderationError(err) {
  const msg = String(err);
  if (/session/i.test(msg)) return error(401, msg);
  if (/unauthorized/i.test(msg)) return error(403, msg);
  if (/not found/i.test(msg)) return error(404, msg);
  return error(400, msg);
}

async function handleAdminScoreboard(actor, sessionId, gameId, scoreboardId) {
  if (!sessionId) return error(401, "Missing session token");
  try {
    const result = await actor.getScoreboardAdminBySession(sessionId, gameId, scoreboardId);
    if (result?.ok) {
      return success({
        entries: result.ok.map((e) => ({
          playerKey: e.playerKey,
          nickname: e.nickname,
          score: Number(e.score),
          streak: Number(e.streak),
          submittedAt: exactNat(e.submittedAt),
          authType: e.authType,
          rank: Number(e.rank),
        })),
      });
    }
    if (result?.err) return moderationError(result.err);
    return error(500, "Unexpected response");
  } catch (e) {
    console.error("[Moderation] Admin board error:", e);
    return error(500, "Failed to load board");
  }
}

async function handleRemoveScoreEntry(actor, sessionId, gameId, scoreboardId, playerKey, purgeArchives) {
  if (!sessionId) return error(401, "Missing session token");
  if (!playerKey) return error(400, "Missing player key");
  try {
    const result = await actor.removeScoreEntryBySession(sessionId, gameId, scoreboardId, playerKey, purgeArchives);
    if (result?.ok !== undefined) return success({ message: result.ok });
    if (result?.err) return moderationError(result.err);
    return error(500, "Unexpected response");
  } catch (e) {
    console.error("[Moderation] Remove entry error:", e);
    return error(500, "Failed to remove entry");
  }
}

async function handleRemovePlayerScores(actor, sessionId, gameId, playerKey, purgeArchives) {
  if (!sessionId) return error(401, "Missing session token");
  if (!playerKey) return error(400, "Missing player key");
  try {
    const result = await actor.removePlayerScoresBySession(sessionId, gameId, playerKey, purgeArchives);
    if (result?.ok !== undefined) return success({ message: result.ok });
    if (result?.err) return moderationError(result.err);
    return error(500, "Unexpected response");
  } catch (e) {
    console.error("[Moderation] Remove player error:", e);
    return error(500, "Failed to remove player scores");
  }
}

async function handleDeletionLog(actor, sessionId, gameId) {
  if (!sessionId) return error(401, "Missing session token");
  try {
    const result = await actor.getEntryDeletionLogBySession(sessionId, gameId);
    if (result?.ok) {
      return success({
        log: result.ok.map((rec) => ({
          scope: rec.scope,
          playerKey: rec.playerKey,
          nickname: rec.nickname,
          liveRemoved: Number(rec.liveRemoved),
          archiveRemoved: Number(rec.archiveRemoved),
          profileReset: rec.profileReset,
          timestamp: exactNat(rec.timestamp),
        })),
      });
    }
    if (result?.err) return moderationError(result.err);
    return error(500, "Unexpected response");
  } catch (e) {
    console.error("[Moderation] Deletion log error:", e);
    return error(500, "Failed to load deletion log");
  }
}

export async function handler(event) {
  // Bind this request's Origin to its async chain (see requestContext above)
  // before anything that can await, so every respond()/error() on this
  // request, however deep, sees its own origin and never a neighbour's.
  const origin = event.headers?.origin || event.headers?.Origin;
  return requestContext.run({ origin }, () => handleRequest(event));
}

async function handleRequest(event) {
  if (event.httpMethod === "OPTIONS") {
    // Let browsers cache the preflight result so every POST doesn't cost a
    // second (tiny but real) function invocation. Browsers cap this
    // internally (Chrome: 2h) regardless of the value sent.
    return {
      statusCode: 204,
      headers: { ...getResponseHeaders(currentOrigin()), "Access-Control-Max-Age": "86400" },
      body: "",
    };
  }

  const method = event.httpMethod;
  const path = event.path.replace("/.netlify/functions/api", "").replace("/api", "") || "/";
  const pathParts = path.split("/").filter(Boolean);
  const query = event.queryStringParameters || {};
  
  let body = {};
  if (event.body) {
    try {
      body = JSON.parse(event.body);
    } catch (e) {
      return error(400, "Invalid JSON body");
    }
  }
  
  const apiKey = event.headers["x-api-key"] || event.headers["X-API-Key"];
  const sessionToken = event.headers["x-session-token"] || event.headers["X-Session-Token"] || 
                       event.headers["authorization"]?.replace("Bearer ", "");
  const gameIdHeader = event.headers["x-game-id"] || event.headers["X-Game-ID"] || query.game_id;
  
  // Reject duplicate rapid-fire score submits before we pay for actor
  // creation or a canister call. See writeGuardTimes above for the full
  // rationale. body.playerId is absent on session submits (identity is the
  // session itself) so those key on the token alone.
  if (method === "POST" && pathParts[0] === "scores" && (apiKey || sessionToken)) {
    const guardKey = `${apiKey || sessionToken}:${body.playerId || "session"}:${body.scoreboardId || "main"}`;
    const lastWrite = writeGuardTimes.get(guardKey);
    const nowMs = Date.now();
    if (lastWrite !== undefined && (nowMs - lastWrite) < WRITE_GUARD_WINDOW_MS) {
      const guardWho = body.playerId ? fp(body.playerId) : "session";
      logJson(`[CheddaAPI] POST /scores guard-reject board=${cleanForLog(body.scoreboardId || "main")} player=${guardWho}`, { evt: "guard_reject", board: cleanForLog(body.scoreboardId || "main"), player: guardWho });
      return error(400, "Please wait 2 seconds between submissions.");
    }
    writeGuardTimes.delete(guardKey);
    boundedSet(writeGuardTimes, guardKey, nowMs, WRITE_GUARD_MAX_ENTRIES, (t) => (nowMs - t) >= WRITE_GUARD_WINDOW_MS);
  }

  let actor;
  try {
    actor = await getActor();
  } catch (e) {
    return error(503, "Backend temporarily unavailable");
  }
  
  // X-Game-ID logged so header-keyed reads (/leaderboard, /players/...) can be
  // attributed per game; /games/:id/... paths already carry it in the path.
  const clientIp = getClientIp(event.headers || {});
  logJson(`[CheddaAPI] ${method} ${cleanForLog(path)}`, { evt: "request", method, path: cleanForLog(path), ...(gameIdHeader ? { game: cleanForLog(gameIdHeader) } : {}), ...(clientIp ? { ip: clientIp } : {}) });
  
  // Path-segment hygiene: reject malformed game/board IDs before they reach
  // the canister. Charset is [A-Za-z0-9_-] (mixed case allowed: older
  // mixed-case game IDs are grandfathered). Seen in the wild
  // 2026-08-19: a client-side C string bug sent GET /games/<garbage
  // bytes>/scoreboards/bc07 — harmless (lookup missed) but it burned a
  // canister call and put raw bytes in the logs. Fail fast with a clear
  // error instead.
  const ID_SEGMENT = /^[A-Za-z0-9_-]{1,64}$/;
  if (pathParts[0] === "games" && pathParts[1] && !ID_SEGMENT.test(pathParts[1])) {
    return error(400, "Invalid game ID in path: only letters, numbers, hyphens and underscores are allowed");
  }
  if (pathParts[0] === "games" && pathParts[2] === "scoreboards" && pathParts[3] && !ID_SEGMENT.test(pathParts[3])) {
    return error(400, "Invalid scoreboard ID in path: only letters, numbers, hyphens and underscores are allowed");
  }
  
  try {
    // =====================================================
    // AUTH ROUTES
    // =====================================================
    
    if (method === "POST" && pathParts[0] === "auth" && pathParts[1] === "google") {
      const limited = routeLimit("social_ip", socialIpKey(clientIp), LIMIT_SOCIAL_AUTH_PER_IP_HOUR, 3600000);
      if (limited) return limited;
      return await handleGoogleAuth(actor, body, gameIdHeader || body.gameId);
    }
    
    if (method === "POST" && pathParts[0] === "auth" && pathParts[1] === "apple") {
      const limited = routeLimit("social_ip", socialIpKey(clientIp), LIMIT_SOCIAL_AUTH_PER_IP_HOUR, 3600000);
      if (limited) return limited;
      return await handleAppleAuth(actor, body, gameIdHeader || body.gameId);
    }
    
    if (method === "POST" && pathParts[0] === "auth" && pathParts[1] === "anonymous") {
      const limited = routeLimit("anon", clientIp, LIMIT_ANON_AUTH_PER_IP_HOUR, 3600000);
      if (limited) return limited;
      return await handleAnonymousAuth(actor, body, gameIdHeader || body.gameId);
    }
    
    if (method === "GET" && pathParts[0] === "auth" && pathParts[1] === "session") {
      return await handleValidateSession(actor, sessionToken);
    }
    
    if (method === "POST" && pathParts[0] === "auth" && pathParts[1] === "logout") {
      return await handleLogout(actor, sessionToken);
    }
    
    if (method === "GET" && pathParts[0] === "auth" && pathParts[1] === "profile") {
      return await handleGetProfile(actor, sessionToken, gameIdHeader);
    }
    
    if (method === "GET" && pathParts[0] === "auth" && pathParts[1] === "config") {
      const gameId = pathParts[2] || gameIdHeader;
      if (!gameId) return error(400, "Missing game ID");
      
      const oauthConfig = await getGameOAuthConfig(actor, gameId);
      
      return success({
        gameId: gameId,
        google: {
          enabled: (oauthConfig?.googleClientIds?.length > 0) || FALLBACK_GOOGLE_CLIENT_IDS.length > 0,
          clientIdCount: oauthConfig?.googleClientIds?.length || 0,
        },
        apple: {
          enabled: !!oauthConfig?.appleBundleId || !!FALLBACK_APPLE_BUNDLE_ID,
          bundleId: oauthConfig?.appleBundleId ? "[configured]" : null,
        },
        deviceCode: {
          enabled: true,
          verificationUrl: VERIFICATION_URL,
        }
      });
    }
    
    // =====================================================
    // DEVICE CODE AUTH ROUTES (NEW v1.7.0)
    // =====================================================
    
    // POST /auth/device/code - Request a new device code
    if (method === "POST" && pathParts[0] === "auth" && pathParts[1] === "device" && pathParts[2] === "code") {
      const limited = routeLimit("dcode", clientIp, LIMIT_DEVICE_CODE_PER_IP_HOUR, 3600000);
      if (limited) return limited;
      const dcGameId = gameIdHeader || body.gameId;
      if (dcGameId && !ID_SEGMENT.test(dcGameId)) {
        logJson(`[CheddaAPI] device code refused, bad game ID ${cleanForLog(dcGameId)}`, { evt: "device_code_bad_game", game: cleanForLog(dcGameId) });
        return error(400, `Invalid game ID "${cleanForLog(dcGameId)}". Game IDs use lowercase letters, digits and hyphens; copy yours from the dashboard.`);
      }
      if (dcGameId && !(await gameExists(actor, dcGameId))) {
        logJson(`[CheddaAPI] device code refused, unknown game ${cleanForLog(dcGameId)}`, { evt: "device_code_bad_game", game: cleanForLog(dcGameId) });
        return error(400, `Unknown game ID "${cleanForLog(dcGameId)}". Copy your Game ID from the dashboard (cheddaboards.com/developers).`);
      }
      return await handleDeviceCodeRequest(dcGameId, body.nickname);
    }
    
    // POST /auth/device/token - Poll for authorization (game client calls this)
    if (method === "POST" && pathParts[0] === "auth" && pathParts[1] === "device" && pathParts[2] === "token") {
      return await handleDeviceCodeToken(body);
    }
    
    // POST /auth/device/approve - Complete authorization (verification page calls this)
    if (method === "POST" && pathParts[0] === "auth" && pathParts[1] === "device" && pathParts[2] === "approve") {
      const limited = routeLimit("dapprove", clientIp, LIMIT_DEVICE_APPROVE_PER_IP_HOUR, 3600000);
      if (limited) return limited;
      return await handleDeviceCodeApprove(actor, body);
    }
    
    // GET /auth/device/status/:code - Check if a user code is valid (verification page uses this)
    if (method === "GET" && pathParts[0] === "auth" && pathParts[1] === "device" && pathParts[2] === "status") {
      const limited = routeLimit("dstatus", clientIp, LIMIT_DEVICE_STATUS_PER_IP_MIN, 60000);
      if (limited) return limited;
      return await handleDeviceCodeStatus(pathParts[3] || query.code);
    }
    
    // GET /nickname/check?name=xxx - Check if nickname is available
    if (method === "GET" && pathParts[0] === "nickname" && pathParts[1] === "check") {
      const nickname = query.name;
      const gameId = gameIdHeader;
      if (!gameId) return error(400, "Missing X-Game-ID header");
      return await handleNicknameCheck(actor, nickname, gameId);
    }
    
    // =====================================================
    // PLAY SESSION ROUTES (NEW v1.5.0)
    // =====================================================
    
    // POST /play-sessions/start - Start a play session (API key auth)
    if (method === "POST" && pathParts[0] === "play-sessions" && pathParts[1] === "start") {
      // Check for API key first
      if (apiKey) {
        const keyValidation = await validateApiKeyAsync(apiKey, actor, gameIdHeader, false);  // sessions don't spend the tier budget
        if (!keyValidation.valid) {
          const code = keyValidation.retryAfter ? 429 : 401;
          return error(code, keyValidation.error, keyValidation.retryAfter ? { "Retry-After": String(keyValidation.retryAfter) } : {});
        }
        // SECURITY-AUDIT 2026-10-25: a start that goes to the canister is an
        // update call, so it spends the tier budget. Starts served locally
        // (validation off, skip token minted here) stay free.
        const skipFlag = skipValidationGames.get(keyValidation.gameId);
        const servedLocally = skipFlag && (Date.now() - skipFlag) < SKIP_VALIDATION_TTL;
        if (!servedLocally) {
          const spend = checkRateLimit(apiKey, keyValidation.tier, true);
          if (!spend.allowed) return error(429, spend.error, { "Retry-After": String(spend.retryAfter) });
        }
        return await handleStartPlaySession(actor, apiKey, keyValidation.gameId, body, keyValidation.rateLimit);
      }

      // Check for session token (OAuth users)
      if (sessionToken) {
        const gameId = gameIdHeader || body.gameId;
        if (!gameId) return error(400, "Missing game ID");
        const limited = routeLimit("psess", fp(sessionToken), LIMIT_SESSION_PLAY_PER_SESSION_HOUR, 3600000);
        if (limited) return limited;
        return await handleStartPlaySessionBySession(actor, sessionToken, gameId);
      }
      
      return error(401, "API key or session token required");
    }
    
    // GET /play-sessions/:token/status - Check play session status
    if (method === "GET" && pathParts[0] === "play-sessions" && pathParts[2] === "status") {
      const token = pathParts[1];
      return await handleGetPlaySessionStatus(actor, token);
    }
    
    // POST /play-sessions/end - End/cancel a play session
    if (method === "POST" && pathParts[0] === "play-sessions" && pathParts[1] === "end") {
      // Check for API key first
      if (apiKey) {
        const keyValidation = await validateApiKeyAsync(apiKey, actor, gameIdHeader, false);  // sessions don't spend the tier budget
        if (!keyValidation.valid) {
          const code = keyValidation.retryAfter ? 429 : 401;
          return error(code, keyValidation.error, keyValidation.retryAfter ? { "Retry-After": String(keyValidation.retryAfter) } : {});
        }
        // Same rule as start: only a real canister cancel spends budget.
        const endTok = typeof body.playSessionToken === "string" ? body.playSessionToken : "";
        if (endTok && !endTok.startsWith("skip_validation_")) {
          const spend = checkRateLimit(apiKey, keyValidation.tier, true);
          if (!spend.allowed) return error(429, spend.error, { "Retry-After": String(spend.retryAfter) });
        }
        return await handleEndPlaySessionByApiKey(actor, body, keyValidation.rateLimit);
      }

      // Check for session token (OAuth users)
      if (sessionToken) {
        const limited = routeLimit("psess", fp(sessionToken), LIMIT_SESSION_PLAY_PER_SESSION_HOUR, 3600000);
        if (limited) return limited;
        return await handleEndPlaySessionBySession(actor, sessionToken, body);
      }
      
      return error(401, "API key or session token required");
    }
    
    // =====================================================
    // SCOREBOARD ROUTES (Public)
    // =====================================================
    
    if (method === "GET" && pathParts[0] === "games" && pathParts[2] === "scoreboards" && !pathParts[3]) {
      const gameId = pathParts[1];
      return await handleListScoreboards(actor, gameId);
    }
    
    if (method === "GET" && pathParts[0] === "games" && pathParts[2] === "scoreboards" && pathParts[3] && pathParts[4] === "admin") {
      return await handleAdminScoreboard(actor, sessionToken, pathParts[1], pathParts[3]);
    }

    if (method === "GET" && pathParts[0] === "games" && pathParts[2] === "deletion-log") {
      return await handleDeletionLog(actor, sessionToken, pathParts[1]);
    }

    if (method === "GET" && pathParts[0] === "games" && pathParts[2] === "scoreboards" && pathParts[3] && 
        pathParts[4] !== "rank" && pathParts[4] !== "archives" && pathParts[4] !== "admin") {
      const gameId = pathParts[1];
      const scoreboardId = pathParts[3];
      const limit = parseLimit(query);
      return await handleGetScoreboard(actor, gameId, scoreboardId, limit);
    }
    
    if (method === "GET" && pathParts[0] === "games" && pathParts[2] === "scoreboards" && pathParts[3] && pathParts[4] === "rank") {
      const gameId = pathParts[1];
      const scoreboardId = pathParts[3];
      
      if (!sessionToken) {
        return error(401, "Session required to get player rank");
      }
      
      return await handleGetPlayerRank(actor, gameId, scoreboardId, sessionToken);
    }
    
    // =====================================================
    // SCOREBOARD ARCHIVE ROUTES (NEW v1.4.0)
    // =====================================================
    
    // GET /games/:gameId/scoreboards/:scoreboardId/archives
    if (method === "GET" && pathParts[0] === "games" && pathParts[2] === "scoreboards" && 
        pathParts[3] && pathParts[4] === "archives" && !pathParts[5]) {
      const gameId = pathParts[1];
      const scoreboardId = pathParts[3];
      return await handleListArchives(actor, gameId, scoreboardId, query);
    }
    
    // GET /games/:gameId/scoreboards/:scoreboardId/archives/latest
    if (method === "GET" && pathParts[0] === "games" && pathParts[2] === "scoreboards" && 
        pathParts[3] && pathParts[4] === "archives" && pathParts[5] === "latest") {
      const gameId = pathParts[1];
      const scoreboardId = pathParts[3];
      const limit = parseLimit(query);
      return await handleGetLastArchive(actor, gameId, scoreboardId, limit);
    }
    
    // GET /archives/:archiveId
    if (method === "GET" && pathParts[0] === "archives" && pathParts[1]) {
      const archiveId = decodeURIComponent(pathParts.slice(1).join("/"));
      const limit = parseLimit(query);
      return await handleGetArchive(actor, archiveId, limit);
    }
    
    // GET /games/:gameId/archives/stats
    if (method === "GET" && pathParts[0] === "games" && pathParts[2] === "archives" && pathParts[3] === "stats") {
      const gameId = pathParts[1];
      return await handleGetArchiveStats(actor, gameId);
    }
    
    // =====================================================
    // SCOREBOARD ROUTES (Developer)
    // =====================================================
    
    if (method === "POST" && pathParts[0] === "games" && pathParts[2] === "scoreboards" && !pathParts[3]) {
      const gameId = pathParts[1];
      return await handleCreateScoreboard(actor, sessionToken, gameId, body);
    }
    
    if (method === "POST" && pathParts[0] === "games" && pathParts[2] === "scoreboards" && pathParts[3] && pathParts[4] === "reset") {
      const gameId = pathParts[1];
      const scoreboardId = pathParts[3];
      return await handleResetScoreboard(actor, sessionToken, gameId, scoreboardId);
    }
    
    if (method === "DELETE" && pathParts[0] === "games" && pathParts[2] === "scoreboards" && pathParts[3] && pathParts[4] === "entries" && pathParts[5]) {
      const purge = query.archives === "true";
      return await handleRemoveScoreEntry(actor, sessionToken, pathParts[1], pathParts[3], pathParts[5], purge);
    }

    if (method === "DELETE" && pathParts[0] === "games" && pathParts[2] === "players" && pathParts[3] && pathParts[4] === "scores") {
      const purge = query.archives === "true";
      return await handleRemovePlayerScores(actor, sessionToken, pathParts[1], pathParts[3], purge);
    }

    if (method === "DELETE" && pathParts[0] === "games" && pathParts[2] === "scoreboards" && pathParts[3] && !pathParts[4]) {
      const gameId = pathParts[1];
      const scoreboardId = pathParts[3];
      return await handleDeleteScoreboard(actor, sessionToken, gameId, scoreboardId);
    }
    
    // =====================================================
    // SESSION-BASED ROUTES
    // =====================================================
    
    if (sessionToken && !apiKey) {
      const gameId = gameIdHeader || body.gameId;
      
      // POST /migrate-account - Upgrade anonymous account to verified
      if (method === "POST" && pathParts[0] === "migrate-account") {
        return await handleMigrateAccount(actor, sessionToken, body);
      }
      
      if (!gameId && !["auth", "games", "archives", "play-sessions", "migrate-account", "request-upgrade", "health", "stats", "docs"].includes(pathParts[0]) && path !== "/") {
        return error(400, "Missing X-Game-ID header or gameId in body");
      }
      
      if (method === "POST" && pathParts[0] === "scores") {
        // SECURITY-AUDIT 2026-10-25: session submits now get the per-player
        // cap too, keyed on the session. Before, an anonymous session (free
        // to mint) had only the 2s write guard and the IP cap.
        const capped = checkSubmitCeiling(gameId, clientIp, `sess_${fp(sessionToken)}`);
        if (capped) return capped;
        return await handleSessionSubmitScore(actor, sessionToken, gameId, body);
      }
      
      if (method === "POST" && pathParts[0] === "achievements") {
        return await handleSessionUnlockAchievement(actor, sessionToken, gameId, body);
      }
      
      if (method === "PUT" && pathParts[0] === "profile" && pathParts[1] === "nickname") {
        return await handleSessionChangeNickname(actor, sessionToken, gameId, body);
      }
      
      // GET /players/:playerId/rank - same SDK call from a linked (session)
      // player: the session identifies them, so the path's player ID is ignored.
      if (method === "GET" && pathParts[0] === "players" && pathParts[2] === "rank") {
        const rankBoard = query.board || "all-time";
        if (!ID_SEGMENT.test(rankBoard)) return error(400, "Invalid board ID");
        return await handleGetPlayerRank(actor, gameId, rankBoard, sessionToken);
      }
      
      if (method === "GET" && pathParts[0] === "leaderboard") {
        return await handleGetLeaderboard(actor, gameId, query);
      }
      
      if (method === "GET" && pathParts[0] === "game" && !pathParts[1]) {
        return await handleGetGameInfo(actor, gameId);
      }
    }
    
    // =====================================================
    // API KEY ROUTES
    // =====================================================
    
    if (apiKey) {
      // Only canister writes spend the per-key tier budget (2026-10-17, see
      // checkRateLimit). Reads and everything else still validate the key
      // but can't be rejected by the limit.
      const countsAgainstLimit = isTierCountedRequest(method, pathParts);
      const keyValidation = await validateApiKeyAsync(apiKey, actor, gameIdHeader, countsAgainstLimit);
      if (!keyValidation.valid) {
        const code = keyValidation.retryAfter ? 429 : 401;
        if (code === 429) {
          // Tier limit hit (checkRateLimit). Logged so the daily summaries can
          // see who is pressing on the per-key ceiling.
          logJson(`[CheddaAPI] tier rate limit game=${cleanForLog(gameIdHeader || "?")} path=${method} /${pathParts.join("/")}`, { evt: "submit_cap_reject", scope: "tier", game: cleanForLog(gameIdHeader || "?"), path: `${method} /${pathParts.join("/")}`, ...(clientIp ? { ip: clientIp } : {}) });
        }
        return error(code, keyValidation.error, keyValidation.retryAfter ? { "Retry-After": String(keyValidation.retryAfter) } : {});
      }
      
      const gameId = keyValidation.gameId;
      const rateLimit = keyValidation.rateLimit;
      
      if (method === "POST" && pathParts[0] === "scores") {
        const capped = checkSubmitCeiling(gameId, clientIp, body?.playerId);
        if (capped) return capped;
        return await handleExternalSubmitScore(actor, apiKey, gameId, body, rateLimit);
      }
      
      // POST /achievements - Unlock achievement(s) - supports batch via achievementIds array
      if (method === "POST" && pathParts[0] === "achievements") {
        const { playerId, achievementId, achievementIds } = body;
        if (!playerId) return error(400, "Missing required field: playerId");
        
        // Support both single (achievementId) and batch (achievementIds)
        const idsToUnlock = achievementIds || (achievementId ? [achievementId] : []);
        const badIds = achievementIdsError(idsToUnlock);
        if (badIds) return error(400, badIds);
        const achLimited = routeLimit("ach", `${gameId}:${fp(playerId)}`, LIMIT_ACHIEVEMENT_CALLS_PER_PLAYER_HOUR, 3600000);
        if (achLimited) return achLimited;
        
        try {
          const outcome = await unlockAchievementsBatched(actor, "external", playerId, gameId, idsToUnlock);
          if (outcome.batchError !== undefined) {
            return error(400, outcome.batchError);
          }
          const { results, successCount } = outcome;
          return success({ 
            message: `${successCount}/${idsToUnlock.length} achievements unlocked`,
            unlocked: successCount,
            total: idsToUnlock.length,
            results 
          }, { "X-RateLimit-Remaining": String(rateLimit?.hour || 0) });
        } catch (e) {
          console.error("[API] Achievement unlock error:", e);
          return error(500, "Failed to unlock achievements");
        }
      }
      
      if (method === "PUT" && pathParts[0] === "players" && pathParts[2] === "nickname") {
        const playerId = pathParts[1];
        return await handleExternalChangeNickname(actor, gameId, playerId, body, rateLimit);
      }
      
      // GET /players/:playerId/rank - rank for an anonymous/external player
      if (method === "GET" && pathParts[0] === "players" && pathParts[1] && pathParts[2] === "rank") {
        return await handleExternalPlayerRank(actor, gameId, pathParts[1], query, rateLimit);
      }
      
      if (method === "GET" && pathParts[0] === "players" && pathParts[2] === "profile") {
        const playerId = pathParts[1];
        try {
          const result = await actor.getUserProfile("external", playerId);
          if (result?.ok) {
            const profile = result.ok;
            let gameProfile = null;
            for (const [gId, gp] of profile.gameProfiles) {
              if (gId === gameId) {
                gameProfile = {
                  score: Number(gp.total_score),
                  streak: Number(gp.best_streak),
                  achievements: gp.achievements,
                  playCount: Number(gp.play_count),
                  lastPlayed: exactNat(gp.last_played),
                };
                break;
              }
            }
            return success({
              nickname: profile.nickname,
              created: exactNat(profile.created),
              gameProfile: gameProfile,
            }, { "X-RateLimit-Remaining": String(rateLimit?.hour || 0) });
          }
          return error(404, result?.err || "Player not found");
        } catch (e) {
          console.error("[API] Get external profile error:", e);
          return error(500, "Failed to fetch player profile");
        }
      }
      
      if (method === "GET" && pathParts[0] === "leaderboard") {
        return await handleGetLeaderboard(actor, gameId, query);
      }
      
      if (method === "GET" && pathParts[0] === "game" && !pathParts[1]) {
        return await handleGetGameInfo(actor, gameId);
      }
      
      if (method === "GET" && pathParts[0] === "scoreboards" && !pathParts[1]) {
        return await handleListScoreboards(actor, gameId);
      }
      
      if (method === "GET" && pathParts[0] === "scoreboards" && pathParts[1] && pathParts[2] !== "archives") {
        const scoreboardId = pathParts[1];
        const limit = parseLimit(query);
        return await handleGetScoreboard(actor, gameId, scoreboardId, limit);
      }
      
      // API Key archive routes
      if (method === "GET" && pathParts[0] === "scoreboards" && pathParts[1] && pathParts[2] === "archives" && !pathParts[3]) {
        const scoreboardId = pathParts[1];
        return await handleListArchives(actor, gameId, scoreboardId, query);
      }
      
      if (method === "GET" && pathParts[0] === "scoreboards" && pathParts[1] && pathParts[2] === "archives" && pathParts[3] === "latest") {
        const scoreboardId = pathParts[1];
        const limit = parseLimit(query);
        return await handleGetLastArchive(actor, gameId, scoreboardId, limit);
      }
      
      if (method === "GET" && pathParts[0] === "archives" && pathParts[1] === "stats") {
        return await handleGetArchiveStats(actor, gameId);
      }
      
      if (method === "GET" && (path === "/" || path === "/health")) {
        return success({ status: "healthy", version: API_VERSION, gameId, tier: keyValidation.tier, auth: "api_key" });
      }
    }
    
    // =====================================================
    // OAUTH MANAGEMENT ROUTES
    // =====================================================
    
    // SECURITY 2026-10-25 (audit C1): per-game OAuth credentials are retired.
    // No game had any set (census 2026-10-25), and the auth handlers no longer
    // read them, so registering new ones is refused rather than silently ignored.
    if (method === "POST" && pathParts[0] === "games" && pathParts[2] === "oauth" &&
        (pathParts[3] === "google" || pathParts[3] === "apple")) {
      return error(410, "Per-game OAuth credentials are no longer supported. Players sign in through the CheddaBoards link page.");
    }
    
    if (method === "POST" && pathParts[0] === "games" && pathParts[2] === "oauth" && pathParts[3] === "google") {
      const gameId = pathParts[1];
      const { clientIds } = body;
      
      if (!sessionToken) {
        return error(401, "Session required. Login first.");
      }
      
      if (!clientIds || !Array.isArray(clientIds)) {
        return error(400, "clientIds must be an array of Google OAuth client IDs");
      }
      
      for (const id of clientIds) {
        if (!id.endsWith(".apps.googleusercontent.com")) {
          return error(400, `Invalid client ID format: ${id}. Must end with .apps.googleusercontent.com`);
        }
      }
      
      try {
        const result = await actor.setGameGoogleCredentialsBySession(sessionToken, gameId, clientIds);
        
        if (result?.ok) {
          oauthConfigCache.delete(gameId);
          return success({ message: result.ok, clientIdCount: clientIds.length });
        }
        if (result?.err) {
          return error(400, result.err);
        }
        return error(500, "Unexpected response");
      } catch (e) {
        console.error("[OAuth] Set Google credentials error:", e);
        return error(500, "Failed to save Google credentials");
      }
    }
    
    if (method === "POST" && pathParts[0] === "games" && pathParts[2] === "oauth" && pathParts[3] === "apple") {
      const gameId = pathParts[1];
      const { bundleId, teamId } = body;
      
      if (!sessionToken) {
        return error(401, "Session required. Login first.");
      }
      
      if (!bundleId) {
        return error(400, "bundleId is required (e.g., com.company.appname)");
      }
      
      if (!bundleId.includes(".") || bundleId.length < 5) {
        return error(400, "Invalid bundle ID format. Expected: com.company.appname");
      }
      
      try {
        const result = await actor.setGameAppleCredentialsBySession(
          sessionToken, 
          gameId, 
          bundleId, 
          teamId ? [teamId] : []
        );
        
        if (result?.ok) {
          oauthConfigCache.delete(gameId);
          return success({ message: result.ok, bundleId });
        }
        if (result?.err) {
          return error(400, result.err);
        }
        return error(500, "Unexpected response");
      } catch (e) {
        console.error("[OAuth] Set Apple credentials error:", e);
        return error(500, "Failed to save Apple credentials");
      }
    }
    
    if (method === "GET" && pathParts[0] === "games" && pathParts[2] === "oauth" && !pathParts[3]) {
      const gameId = pathParts[1];
      
      if (!sessionToken) {
        return error(401, "Session required");
      }
      
      try {
        const result = await actor.getGameOAuthConfigBySession(sessionToken, gameId);
        
        if (result?.ok) {
          const config = result.ok;
          return success({
            google: {
              configured: config.googleConfigured,
              clientIds: config.googleClientIds,
            },
            apple: {
              configured: config.appleConfigured,
              bundleId: config.appleBundleId || null,
              teamId: config.appleTeamId || null,
            }
          });
        }
        if (result?.err) {
          return error(400, result.err);
        }
        return error(500, "Unexpected response");
      } catch (e) {
        console.error("[OAuth] Get config error:", e);
        return error(500, "Failed to fetch OAuth config");
      }
    }
    
    if (method === "DELETE" && pathParts[0] === "games" && pathParts[2] === "oauth" && pathParts[3] === "google") {
      const gameId = pathParts[1];
      
      if (!sessionToken) {
        return error(401, "Session required");
      }
      
      try {
        const result = await actor.clearGameOAuthCredentialsBySession(sessionToken, gameId, "google");
        
        if (result?.ok) {
          oauthConfigCache.delete(gameId);
          return success({ message: result.ok });
        }
        if (result?.err) {
          return error(400, result.err);
        }
        return error(500, "Unexpected response");
      } catch (e) {
        return error(500, "Failed to clear Google credentials");
      }
    }
    
    if (method === "DELETE" && pathParts[0] === "games" && pathParts[2] === "oauth" && pathParts[3] === "apple") {
      const gameId = pathParts[1];
      
      if (!sessionToken) {
        return error(401, "Session required");
      }
      
      try {
        const result = await actor.clearGameOAuthCredentialsBySession(sessionToken, gameId, "apple");
        
        if (result?.ok) {
          oauthConfigCache.delete(gameId);
          return success({ message: result.ok });
        }
        if (result?.err) {
          return error(400, result.err);
        }
        return error(500, "Unexpected response");
      } catch (e) {
        return error(500, "Failed to clear Apple credentials");
      }
    }
    
    // =====================================================
    // PUBLIC ROUTES
    // =====================================================
    
    if (method === "GET" && (path === "/" || path === "/health")) {
      // Report the build stamp and the principal this proxy signs as, so a deploy
      // can be verified from one request. If signingPrincipal is "2vxsx-fae" the
      // proxy is anonymous (identity not loaded); it must match main.mo's VERIFIER.
      let signingPrincipal = "unknown";
      let identityError = null;
      try {
        const a = await getActor(); // forces identity load + actor creation
        signingPrincipal = (await cachedAgent.getPrincipal()).toText();
      } catch (e) {
        identityError = e && e.message ? e.message : String(e);
      }
      return success({
        status: "healthy",
        version: API_VERSION,
        build: BUILD_STAMP,
        submitCaps: { ipPerMin: SUBMIT_CAP_IP_PER_MIN, pausedGames: PAUSED_GAMES.size },
        // Caller's own forwarding chain, for setting CLIENT_IP_HOPS (see getClientIp).
        clientIp: { chain: xffChain(event.headers || {}).map(cleanForLog), hops: CLIENT_IP_HOPS, resolved: clientIp },
        signingPrincipal,
        identityError,
        auth: "none",
      });
    }
    
    // GET /stats — public: total scores CheddaBoards has recorded since launch.
    // Backed by the canister's getSubmissionStats() query (no auth). Safe to call
    // from a public marketing site. Cached briefly to shield the canister from
    // a hammered counter widget.
    if (method === "GET" && path === "/stats") {
      try {
        const now = Date.now();
        if (statsCache && (now - statsCacheTime) < STATS_CACHE_TTL_MS) {
          return success(statsCache);
        }
        const actor = await getActor();
        const s = await actor.getSubmissionStats();
        const payload = {
          totalScores: Number(s.total),
          today: Number(s.today),
        };
        statsCache = payload;
        statsCacheTime = now;
        return success(payload);
      } catch (e) {
        // On failure, serve the last good value if we have one, else a soft error.
        if (statsCache) return success(statsCache);
        return error(503, "Stats temporarily unavailable");
      }
    }
    
    // POST /request-upgrade — a developer clicks "Request More Slots" in the
    // dashboard. We email info@cheddaboards.com (via Resend) with their details
    // and a ready-to-paste upgradeDeveloper command, then the admin runs it.
    //
    // SECURITY-AUDIT 2026-10-25: the old email check (^[^\s@]+@...) allowed
    // quotes, $( ) and |, and the address went straight into a shell command
    // inside single quotes. A crafted "email" broke out of the quotes and ran
    // whatever it liked when the admin pasted the command. Now:
    //   - the email comes from the dashboard session when one is sent
    //     (X-Session-Token), so nobody can request upgrades for someone else;
    //   - every email must match a strict charset with no shell metacharacters;
    //   - per-IP limit on top of the per-email cooldown.
    // Set UPGRADE_REQUIRE_SESSION=1 once the dashboard sends the session header,
    // to stop accepting the body email at all.
    if (method === "POST" && path === "/request-upgrade") {
      try {
        const limited = routeLimit("upgrade", clientIp, LIMIT_UPGRADE_REQ_PER_IP_HOUR, 3600000);
        if (limited) return limited;

        let devEmail = "";
        let verifiedBySession = false;
        if (sessionToken) {
          const sess = await actor.validateSession(sessionToken);
          if (!sess?.ok) return error(401, "Session invalid. Sign in to the dashboard again.");
          devEmail = String(sess.ok.email || "").trim();
          verifiedBySession = true;
        } else if (process.env.UPGRADE_REQUIRE_SESSION === "1") {
          return error(401, "Sign in to the dashboard to request more slots.");
        } else {
          devEmail = String(body.email || "").trim();
        }
        const currentGames = Number(body.currentGames);
        const gamesText = Number.isFinite(currentGames) ? String(currentGames) : "unknown";

        // Strict: letters, digits and . _ % + - only. Nothing a shell treats
        // specially, so the command below can't be broken out of.
        if (!devEmail || devEmail.length > 254 ||
            !/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(devEmail)) {
          return error(400, "A valid account email is required");
        }

        // Simple in-memory rate guard: same email can't spam requests.
        const nowMs = Date.now();
        const last = upgradeRequestTimes.get(devEmail) || 0;
        // (map is bounded below; entries older than the cooldown are dead)
        if (nowMs - last < UPGRADE_REQUEST_COOLDOWN_MS) {
          // Pretend success so the UX is clean; we just don't re-send.
          return success({ sent: true, deduped: true });
        }

        const apiKey = process.env.RESEND_API_KEY;
        if (!apiKey) {
          console.error("[request-upgrade] RESEND_API_KEY not set");
          return error(503, "Upgrade requests are temporarily unavailable");
        }

        const upgradeCmd =
          `dfx canister --network ic call cheddaboards_v2_backend adminGate '("upgradeDeveloper", vec {"${devEmail}"})'`;

        // Configurable via env so you can switch addresses without a code change:
        //  - UPGRADE_EMAIL_TO (required): where notifications land. On Resend's
        //    sandbox sender (onboarding@resend.dev) this MUST be your Resend
        //    signup email; after verifying your domain, use any address on it.
        //  - UPGRADE_EMAIL_FROM: defaults to the sandbox sender; set to an
        //    address on your verified domain once it is verified.
        const emailTo = process.env.UPGRADE_EMAIL_TO;
        if (!emailTo) {
          console.error("[request-upgrade] UPGRADE_EMAIL_TO not set");
          return error(503, "Upgrade requests are temporarily unavailable");
        }
        const emailFrom = process.env.UPGRADE_EMAIL_FROM || "CheddaBoards <onboarding@resend.dev>";

        const emailResp = await fetch("https://api.resend.com/emails", {
          method: "POST",
          headers: {
            "Authorization": "Bearer " + apiKey,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            from: emailFrom,
            to: [emailTo],
            reply_to: devEmail,
            subject: "🎮 Slot upgrade request — " + devEmail + (verifiedBySession ? "" : " (UNVERIFIED, no session)"),
            text:
              "A developer has requested more game slots (free 3 → pro 10).\n\n" +
              "Account email: " + devEmail + (verifiedBySession ? " (from dashboard session)" : " (typed in, NOT verified: check it owns games before approving)") + "\n" +
              "Current games: " + gamesText + "\n\n" +
              "To approve, run:\n\n" +
              upgradeCmd + "\n",
          }),
        });

        if (!emailResp.ok) {
          const detail = await emailResp.text().catch(() => "");
          console.error("[request-upgrade] Resend failed:", emailResp.status, detail);
          return error(502, "Could not send the request. Please email info@cheddaboards.com directly.");
        }

        boundedSet(upgradeRequestTimes, devEmail, nowMs, 5000, (t) => (nowMs - t) >= UPGRADE_REQUEST_COOLDOWN_MS);
        return success({ sent: true });
      } catch (e) {
        console.error("[request-upgrade] error:", e);
        return error(500, "Could not send the request. Please email info@cheddaboards.com directly.");
      }
    }
    
    if (method === "GET" && path === "/docs") {
      return success({
        version: API_VERSION,
        description: "CheddaBoards - Web3 Gaming Backend",
        baseUrl: "https://api.cheddaboards.com",
        
        authentication: {
          note: "Four auth methods available",
          methods: {
            session: "Use X-Session-Token header after OAuth login",
            apiKey: "Use X-API-Key header for server-to-server",
            gameId: "Use X-Game-ID header to specify game context",
            deviceCode: "Use POST /auth/device/code for cross-platform login (no browser needed in game)",
          }
        },
        
        endpoints: {
          auth: {
            "POST /auth/google": "Sign in with Google",
            "POST /auth/apple": "Sign in with Apple",
            "POST /auth/anonymous": "Create anonymous player",
            "GET /auth/session": "Validate session",
            "POST /auth/logout": "Destroy session",
            "GET /auth/profile": "Get user profile",
            "GET /auth/config/:gameId": "Check available auth methods",
            "GET /nickname/check?name=xxx": "Check if nickname is available",
            "POST /auth/device/code": "Request device code for cross-platform login",
            "POST /auth/device/token": "Poll for device authorization result",
            "POST /auth/device/approve": "Complete device authorization (verification page)",
            "GET /auth/device/status/:code": "Check if user code is valid"
          },
          
          playSessions: {
            "POST /play-sessions/start": "Start a play session (for time validation)",
            "POST /play-sessions/end": "End/cancel a play session {playSessionToken}",
            "GET /play-sessions/:token/status": "Check play session status"
          },
          
          scoreboards: {
            "GET /games/:gameId/scoreboards": "List all scoreboards",
            "GET /games/:gameId/scoreboards/:id": "Get scoreboard entries",
            "GET /games/:gameId/scoreboards/:id/rank": "Get player rank (session)",
            "POST /games/:gameId/scoreboards": "Create scoreboard (dev)",
            "POST /games/:gameId/scoreboards/:id/reset": "Reset scoreboard (dev)",
            "DELETE /games/:gameId/scoreboards/:id": "Delete scoreboard (dev)"
          },
          
          archives: {
            "GET /games/:gameId/scoreboards/:id/archives": "List all archives",
            "GET /games/:gameId/scoreboards/:id/archives/latest": "Get last week's/month's results",
            "GET /archives/:archiveId": "Get specific archive",
            "GET /games/:gameId/archives/stats": "Get archive stats"
          },
          
          gameplay: {
            "POST /scores": "Submit score (include playSessionToken for time validation)",
            "POST /achievements": "Unlock achievement",
            "PUT /profile/nickname": "Change nickname",
            "GET /leaderboard": "Get legacy leaderboard",
            "POST /migrate-account": "Upgrade anonymous account to verified {deviceId}"
          },
          
          apiKey: {
            "POST /play-sessions/start": "Start play session {playerId, gameId}",
            "POST /scores": "Submit score (external)",
            "POST /achievements": "Unlock achievement {playerId, achievementId}",
            "PUT /players/:id/nickname": "Change nickname",
            "GET /players/:id/profile": "Get player profile",
            "GET /scoreboards/:id/archives": "List archives",
            "GET /scoreboards/:id/archives/latest": "Get last archive"
          }
        },
        
        examples: {
          startSession: "POST /play-sessions/start {playerId: 'dev_123', gameId: 'my-game'}",
          submitWithSession: "POST /scores {playerId: 'dev_123', score: 1000, playSessionToken: 'ps_...'}",
          getWeekly: "GET /games/my-game/scoreboards/weekly?limit=10",
          getLastWeek: "GET /games/my-game/scoreboards/weekly/archives/latest",
          listArchives: "GET /games/my-game/scoreboards/weekly/archives",
          deviceCodeFlow: {
            step1: "POST /auth/device/code {gameId: 'my-game'} → returns device_code + user_code",
            step2: "User visits verification_url and enters user_code, signs in with Google/Apple",
            step3: "POST /auth/device/token {device_code: '...'} → poll until session returned",
          }
        }
      });
    }
    
    logJson(`[CheddaAPI] unknown route ${method} ${cleanForLog(path)}`, { evt: "unknown_route", method, path: cleanForLog(path) });
    return error(404, unknownEndpointMessage(method, path));
    
  } catch (e) {
    logError("[CheddaAPI] Unhandled error", e, { evt: "unhandled_err" });
    return error(500, "Internal server error");
  }
}