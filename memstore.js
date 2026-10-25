// memstore.js — in-memory replacement for Netlify Blobs (device-code flow).
// Valid while the service runs with max-instances=1: device codes are
// short-lived, low-volume state; a restart drops pending codes and the
// player's login screen simply issues a new one. If the service ever
// scales past one instance, swap these internals for Firestore/Memorystore
// — the call sites don't change.

const _store = new Map();
const SWEEP_MS = 10 * 60 * 1000;      // sweep cadence
const MAX_AGE_MS = 30 * 60 * 1000;    // hard cap: nothing lives past 30 min

export const memStore = {
  async setJSON(key, value) {
    _store.set(key, { value, at: Date.now() });
  },
  async get(key, _opts) {
    const hit = _store.get(key);
    if (!hit) return null;
    if (Date.now() - hit.at > MAX_AGE_MS) { _store.delete(key); return null; }
    return hit.value;
  },
  async delete(key) {
    _store.delete(key);
  },
};

setInterval(() => {
  const cutoff = Date.now() - MAX_AGE_MS;
  for (const [k, v] of _store) if (v.at < cutoff) _store.delete(k);
}, SWEEP_MS).unref();