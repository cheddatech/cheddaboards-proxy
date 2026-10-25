// server.js — Cloud Run adapter for the Netlify-shaped handler in api.js.
// Maps plain Node req/res onto the { httpMethod, path, headers,
// queryStringParameters, body } event api.js expects, and writes its
// { statusCode, headers, body } result back out. No route logic here —
// api.js remains the single source of truth.

import http from "node:http";
import { handler } from "./api.js";

const PORT = process.env.PORT || 8080;

// Request bodies are buffered in memory before api.js sees them, so cap them.
// The largest legitimate body (a batch achievement unlock) is a few KB.
const MAX_BODY_BYTES = parseInt(process.env.MAX_BODY_BYTES || "", 10) || 64 * 1024;

const server = http.createServer((req, res) => {
  const chunks = [];
  let size = 0;
  let tooLarge = false;

  req.on("data", (c) => {
    if (tooLarge) return;
    size += c.length;
    if (size > MAX_BODY_BYTES) {
      tooLarge = true;
      chunks.length = 0;
      res.writeHead(413, { "content-type": "application/json", "connection": "close" });
      res.end(JSON.stringify({ ok: false, error: "Request body too large" }));
      req.destroy();
      return;
    }
    chunks.push(c);
  });

  req.on("end", async () => {
    if (tooLarge) return;
    try {
      const url = new URL(req.url, "http://localhost");
      const rawBody = Buffer.concat(chunks).toString("utf8");

      const event = {
        httpMethod: req.method,
        path: url.pathname,
        headers: req.headers,
        queryStringParameters: Object.fromEntries(url.searchParams),
        body: rawBody.length ? rawBody : null,
      };

      const result = await handler(event);

      res.writeHead(result.statusCode || 200, result.headers || {});
      res.end(result.body || "");
    } catch (e) {
      console.error("[server] unhandled:", e);
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "Internal server error" }));
    }
  });

  req.on("error", (e) => {
    if (tooLarge) return;
    console.error("[server] request error:", e);
    try { res.writeHead(500); res.end(); } catch {}
  });
});

// Drop clients that dribble headers/bodies slowly instead of holding sockets.
server.headersTimeout = 15_000;
server.requestTimeout = 30_000;

server.listen(PORT, () => console.log(`[server] CheddaBoards proxy listening on ${PORT}`));