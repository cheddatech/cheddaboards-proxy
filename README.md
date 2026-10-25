# CheddaBoards Proxy

The REST API in front of the [CheddaBoards canister](https://github.com/cheddatech/cheddaboards). It is the code behind `api.cheddaboards.com`.

Games talk plain HTTPS to this proxy. The proxy checks the game's API key or the player's Google / Apple sign-in, then calls the canister with its own signing identity, the **verifier**. The canister only accepts privileged calls (minting sessions, writing scores for API-key players) from that identity, and it stores everything and enforces the rules.

**This is a transitional layer.** Logic is moving into the canister over time: board reads already bypass the proxy, and device-code state and API-key submits are next. The aim is for this to shrink to a small token verifier.

## What it does

- **Auth:** Google and Apple ID-token verification against the providers' published keys, anonymous device sessions, and the device-code flow ([RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)) for linking a game client to an account via a code or QR.
- **Scores and achievements:** API-key and session submits, batch achievement unlocks, play-session time validation, and fan-out board conversion.
- **Abuse limits:** tier limits per API key, per-player and per-IP submit caps, a 2-second write guard, limits on unauthenticated routes, and a pause list per game.
- **Reads:** scoreboards, archives and ranks, with short CDN-friendly caching.
- **Dev dashboard routes:** scoreboard management, moderation and OAuth config. Ownership is checked by the canister.

`GET /docs` on a running instance lists every route.

## Running it

Node 20 or later. The files:

- `api.js`, all route logic, exported as a Netlify-style `handler(event)`.
- `server.js`, a plain Node HTTP adapter around that handler. It caps request bodies at 64 KB (`MAX_BODY_BYTES`).
- `memstore.js`, the in-memory key/value store used for device codes.
- `_lib/cheddaboards_v2_backend.did.js`, the canister's Candid bindings. Generate it from the canister repo with `dfx generate`, and regenerate it whenever the canister interface changes.

```
npm ci
CANISTER_ID=... VERIFIER_IDENTITY='...' npm start   # listens on $PORT, default 8080
```

On Cloud Run, `gcloud run deploy <service> --source . --max-instances 1` builds it with buildpacks. No Dockerfile is needed.

> **Single instance only.** Every limiter, cache and the device-code store live in process memory. Run with max-instances = 1 (on Cloud Run: `--max-instances 1`). A second instance halves every limit and breaks device-code login.

Check a deploy with `GET /health`. It reports the build stamp, the principal the proxy signs as (this must match the canister's verifier), and the caller's forwarding chain.

## Environment variables

### Required

| Variable | Purpose |
|---|---|
| `CANISTER_ID` | Your CheddaBoards canister |
| `VERIFIER_IDENTITY` | Serialized Ed25519 identity JSON the proxy signs with. Its principal must be the canister's verifier. Never commit it. |

### Optional

| Variable | Default | Purpose |
|---|---|---|
| `ICP_HOST` | `https://icp-api.io` | IC gateway |
| `GOOGLE_CLIENT_IDS` | none | Comma-separated fallback Google client IDs, for games without their own |
| `APPLE_BUNDLE_ID` | none | Fallback Apple bundle ID |
| `DEVICE_AUTH_GOOGLE_CLIENT_ID` | none | Client ID used by your `/link` verification page |
| `DEVICE_AUTH_APPLE_BUNDLE_ID` | none | Bundle/service ID used by your `/link` page |
| `DEVICE_AUTH_URL` | `https://cheddaboards.com/link` | Verification page shown to players |
| `CLIENT_IP_HOPS` | `0` (leftmost entry) | Where the real client sits in `X-Forwarded-For`, counted from the right. See below. |
| `PAUSED_GAMES` | none | Comma-separated game IDs whose submits get a 503 |
| `SUBMIT_CAP_IP_PER_MIN` | `60` | Score submits per client IP per minute |
| `SUBMIT_CAP_PLAYER_PER_HOUR` | `120` | Submits per (game, player) per hour |
| `LIMIT_ANON_AUTH_PER_IP_HOUR` | `120` | Anonymous sign-ins per IP |
| `LIMIT_DEVICE_CODE_PER_IP_HOUR` | `30` | Device codes requested per IP |
| `LIMIT_DEVICE_APPROVE_PER_IP_HOUR` | `30` | Device-code approvals per IP |
| `LIMIT_DEVICE_STATUS_PER_IP_MIN` | `60` | Device-code status checks per IP |
| `LIMIT_SESSION_PLAY_PER_SESSION_HOUR` | `240` | Play-session start/end calls per signed-in session |
| `LIMIT_ACHIEVEMENT_CALLS_PER_PLAYER_HOUR` | `120` | Achievement unlock calls per player |
| `MAX_ACHIEVEMENTS_PER_REQUEST` | `100` | Batch size cap |
| `DEVICE_CODE_MAX_PENDING` | `5000` | Pending device codes held at once |
| `RESEND_API_KEY` | none | Enables `/request-upgrade` emails (via [Resend](https://resend.com)) |
| `UPGRADE_EMAIL_TO` | none | Where upgrade requests go. Required if `RESEND_API_KEY` is set. |
| `UPGRADE_EMAIL_FROM` | Resend sandbox sender | Sender address |
| `UPGRADE_REQUIRE_SESSION` | off | `1` = only accept upgrade requests carrying a dashboard session |
| `LIMIT_UPGRADE_REQ_PER_IP_HOUR` | `5` | Upgrade requests per IP |

### Setting `CLIENT_IP_HOPS`

Callers control the left of `X-Forwarded-For`; each proxy in front of you appends to the right. Set this before relying on the per-IP limits.

1. Deploy, then run:

   ```
   curl -H "X-Forwarded-For: 1.2.3.4" https://<your-host>/health
   ```

2. In `clientIp.chain`, find your real IP and count its position from the right, where the last entry is 1. Set that number.
3. Run the curl again: `resolved` should be your IP.

If you set the number too low, every player behind your CDN shares one IP and gets throttled together. If you set it too high, callers can choose their own IP.

Behind Firebase Hosting the answer is 2. Hitting Cloud Run directly skips the CDN, so restrict direct access if the per-IP limits matter to you.

## Security

Report vulnerabilities as described in the canister repo's [SECURITY.md](https://github.com/cheddatech/cheddaboards/blob/main/SECURITY.md). Only the latest release is supported.

Game API keys ship inside game clients, so treat them as public. They identify a game, not a trusted caller. Leaderboard integrity comes from play-session validation, the submit caps and dev moderation, not from keeping keys secret.

## License

MIT, © CheddaTech Ltd. See [LICENSE](LICENSE).
