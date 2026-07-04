// keyserver.js
// Minimal client for the keys.openpgp.org "VKS" HTTP API, used to look up a
// recipient's public key by fingerprint (or opt-in email address) so the user
// can visually confirm the fingerprint before trusting the key.
//
// Trust model: the keyserver is NOT trusted to tell the truth about *who* owns
// a key. A by-fingerprint / by-keyid lookup is only meaningful because the
// caller re-derives the fingerprint from the returned key and checks it equals
// what was asked for (see index.js). keys.openpgp.org only serves an
// email→key mapping after the address owner has verified it, but an email
// lookup still yields a key the *user* must confirm out-of-band by comparing
// its fingerprint. This module therefore only fetches bytes; every trust
// decision is made by the caller.
//
// VKS spec (https://keys.openpgp.org/about/api): hex identifiers MUST be
// uppercase and MUST NOT be prefixed with 0x; responses are ASCII-armored with
// content-type application/pgp-keys; a miss is HTTP 404.

const DEFAULT_BASE_URL = "https://keys.openpgp.org";

/** Strip a leading 0x and all whitespace, uppercase. "" if it isn't hex. */
export function normalizeHex(input) {
  const hex = String(input || "").replace(/^0x/i, "").replace(/\s+/g, "").toUpperCase();
  return /^[0-9A-F]+$/.test(hex) ? hex : "";
}

/**
 * Decide how to interpret a free-text query.
 * @returns {{ kind: "email"|"fingerprint"|"keyid"|"invalid", value: string }}
 */
export function classifyQuery(raw) {
  const s = String(raw || "").trim();
  if (s.includes("@")) return { kind: "email", value: s.toLowerCase() };
  const hex = normalizeHex(s);
  if (hex.length === 40 || hex.length === 64) return { kind: "fingerprint", value: hex }; // v4 / v6
  if (hex.length === 16) return { kind: "keyid", value: hex }; // 64-bit long key ID
  return { kind: "invalid", value: s };
}

function baseUrl(opts) {
  return String((opts && opts.baseUrl) || DEFAULT_BASE_URL).replace(/\/+$/, "");
}

async function getArmored(url) {
  let res;
  try {
    res = await fetch(url, { headers: { Accept: "application/pgp-keys" }, redirect: "follow" });
  } catch (_) {
    // Thrown by the browser for a network failure OR a Content-Security-Policy
    // connect-src block (which is how a locked-down host iframe would refuse).
    throw new Error("Could not reach the keyserver — the network request was blocked or failed.");
  }
  if (res.status === 404) return null; // no such key
  if (!res.ok) throw new Error(`Keyserver returned HTTP ${res.status}.`);
  const text = await res.text();
  if (!/BEGIN PGP PUBLIC KEY BLOCK/.test(text)) throw new Error("Keyserver did not return an OpenPGP public key.");
  return text;
}

/** GET the armored key for a full fingerprint, or null if not found. */
export function lookupByFingerprint(fingerprint, opts) {
  const fp = normalizeHex(fingerprint);
  if (fp.length !== 40 && fp.length !== 64) throw new Error("A full 40- or 64-character fingerprint is required.");
  return getArmored(`${baseUrl(opts)}/vks/v1/by-fingerprint/${fp}`);
}

/** GET the armored key for a 64-bit long key ID, or null if not found. */
export function lookupByKeyID(keyid, opts) {
  const id = normalizeHex(keyid);
  if (id.length !== 16) throw new Error("A 16-character long key ID is required.");
  return getArmored(`${baseUrl(opts)}/vks/v1/by-keyid/${id}`);
}

/** GET the armored key for an (owner-verified) email address, or null. */
export function lookupByEmail(email, opts) {
  const e = String(email || "").trim();
  if (!e.includes("@")) throw new Error("A valid email address is required.");
  return getArmored(`${baseUrl(opts)}/vks/v1/by-email/${encodeURIComponent(e)}`);
}

async function postJson(url, body) {
  let res;
  try {
    res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json" }, body: JSON.stringify(body) });
  } catch (_) {
    throw new Error("Could not reach the keyserver — the network request was blocked or failed.");
  }
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    /* non-JSON error body */
  }
  if (!res.ok) throw new Error((json && (json.error || json.message)) || `Keyserver returned HTTP ${res.status}.`);
  return json || {};
}

/**
 * Upload an armored PUBLIC key to the keyserver.
 * @returns {{ key_fpr: string, token: string, status: Record<string,"unpublished"|"pending"|"published"|"revoked"> }}
 */
export function uploadKey(armoredPublicKey, opts) {
  if (!/BEGIN PGP PUBLIC KEY BLOCK/.test(String(armoredPublicKey || ""))) throw new Error("A public key is required to publish.");
  return postJson(`${baseUrl(opts)}/vks/v1/upload`, { keytext: armoredPublicKey });
}

/**
 * Ask the keyserver to email verification links to `addresses` so they become
 * searchable by email. `token` comes from a prior uploadKey() response.
 */
export function requestVerify(token, addresses, opts) {
  if (!token) throw new Error("Missing upload token.");
  return postJson(`${baseUrl(opts)}/vks/v1/request-verify`, { token, addresses, locale: [] });
}

/**
 * Look up a key from a free-text query (fingerprint, key ID, or email).
 * @returns {{ query: ReturnType<classifyQuery>, armored: string|null }}
 */
export async function lookup(raw, opts) {
  const query = classifyQuery(raw);
  let armored;
  if (query.kind === "email") armored = await lookupByEmail(query.value, opts);
  else if (query.kind === "keyid") armored = await lookupByKeyID(query.value, opts);
  else if (query.kind === "fingerprint") armored = await lookupByFingerprint(query.value, opts);
  else throw new Error("Enter a full fingerprint (40 or 64 hex characters), a 16-character key ID, or an email address.");
  return { query, armored };
}
