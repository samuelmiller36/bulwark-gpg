/**
 * OpenPGP — privileged (same-origin) webmail plugin for Bulwark Mail.
 *
 * Runs all cryptography locally with a bundled openpgp.js engine:
 *
 *   • onComposeSend   (intercept)  → build PGP/MIME, sign/encrypt, host.jmap.sendRaw
 *   • onRenderEmailBody (transform) → host.jmap.fetchBlob, decrypt/verify, replace body
 *   • composer-toolbar slot         → per-message Sign / Encrypt toggles + Attach key
 *   • email-banner slot             → signature / encryption status
 *   • settings-section slot         → generate/import/export keys, unlock/lock, recipients
 *
 * The background (hook) iframe and the slot (UI) iframes are SEPARATE documents,
 * so all shared state lives in host.storage / IndexedDB:
 *   - compose intent (sign/encrypt)        → host.storage[INTENT_KEY]
 *   - per-message verify status (banner)   → host.storage[VERIFY_PREFIX + id]
 *   - unlocked secret keys                 → IndexedDB session store (key-storage.js)
 */

const host = require("@plugin-host");
const React = require("react");
const h = React.createElement;
const { useState, useEffect, useCallback } = React;

import * as engine from "./openpgp-engine.js";
import * as store from "./key-storage.js";
import * as pgp from "./pgp-mime.js";
import * as keyserver from "./keyserver.js";

const INTENT_KEY = "composeIntent.v1";
const VERIFY_PREFIX = "verify:";

function settings() {
  return host.plugin?.settings || {};
}

// ─── Privileged-tier capability probe ──────────────────────────────────
// We need in-frame crypto.subtle + IndexedDB, which exist only in the
// privileged (same-origin) tier. Probe once and degrade gracefully rather than
// letting a raw IndexedDB error crash activate() and trip the circuit breaker.

const NOT_PRIVILEGED_MSG =
  "OpenPGP could not start: it is running in the restricted (untrusted) plugin " +
  "sandbox, where in-browser cryptography and key storage are unavailable. This " +
  'plugin must be delivered as an admin-approved bundle with "tier": "privileged".';

let _capable = null;
async function isCapable() {
  if (_capable !== null) return _capable;
  try {
    if (typeof indexedDB === "undefined" || !(crypto && crypto.subtle)) throw new Error("missing apis");
    await new Promise((resolve, reject) => {
      let r;
      try {
        r = indexedDB.open("openpgp-capability-probe");
      } catch (e) {
        reject(e);
        return;
      }
      r.onsuccess = () => {
        try {
          r.result.close();
        } catch {
          /* ignore */
        }
        resolve();
      };
      r.onerror = () => reject(r.error || new Error("indexedDB open failed"));
      r.onblocked = () => resolve();
    });
    _capable = true;
  } catch {
    _capable = false;
  }
  return _capable;
}

// ─── Address + bytes helpers ───────────────────────────────────────────

function parseAddr(value) {
  if (value && typeof value === "object" && value.email) {
    return { name: value.name || undefined, email: String(value.email) };
  }
  const s = String(value || "");
  const m = s.match(/^\s*(?:"?([^"<]*?)"?\s*)?<?\s*([^<>\s]+@[^<>\s]+)\s*>?\s*$/);
  if (m) return { name: (m[1] || "").trim() || undefined, email: m[2] };
  return { email: s.trim() };
}
function addrList(arr) {
  if (!arr) return [];
  return (Array.isArray(arr) ? arr : [arr]).map(parseAddr).filter((a) => a.email);
}
function formatAddrs(arr) {
  return addrList(arr)
    .map((a) => (a.name ? `${a.name} <${a.email}>` : a.email))
    .join(", ");
}
function emailsOf(arr) {
  return addrList(arr).map((a) => a.email.toLowerCase());
}
function toBytes(blobOrBytes) {
  const b = blobOrBytes;
  if (b instanceof Uint8Array) return Promise.resolve(b);
  if (b instanceof ArrayBuffer) return Promise.resolve(new Uint8Array(b));
  if (b && typeof b.arrayBuffer === "function") return b.arrayBuffer().then((ab) => new Uint8Array(ab));
  if (typeof b === "string") return Promise.resolve(new TextEncoder().encode(b));
  return Promise.resolve(new Uint8Array());
}
function strToArrayBuffer(s) {
  const u8 = new TextEncoder().encode(s);
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
}

// ─── Session-key resolution (shared store -> openpgp objects) ──────────

async function unlockedPrivateKeys() {
  const rows = await store.listSessionKeys();
  const keys = [];
  for (const r of rows) {
    try {
      keys.push(await engine.parsePrivateKey(r.armored));
    } catch {
      /* skip a corrupt session entry */
    }
  }
  return keys;
}
async function firstSigningKey() {
  return (await unlockedPrivateKeys())[0] || null;
}

async function resolveRecipientKeys(emails, signerArmoredSelf) {
  const keys = [];
  const missing = [];
  for (const email of emails) {
    const k = await store.findPublicKeyForEmail(email);
    if (k) keys.push(k.armored);
    else missing.push(email);
  }
  if (signerArmoredSelf) keys.push(signerArmoredSelf); // encrypt-to-self so Sent stays readable
  if (missing.length) throw new Error(`No public key stored for: ${missing.join(", ")}`);
  if (keys.length === 0) throw new Error("No recipient public keys available to encrypt to.");
  return [...new Set(keys)];
}

// ─── Compose-send takeover ─────────────────────────────────────────────

async function resolveIntent(req) {
  const pick = (...vals) => {
    for (const v of vals) if (typeof v === "boolean") return v;
    return undefined;
  };
  let sign = pick(req.sign, req.pgpSign, req.intent && req.intent.sign);
  let encrypt = pick(req.encrypt, req.pgpEncrypt, req.intent && req.intent.encrypt);
  let attachKey;
  if (sign === undefined && encrypt === undefined) {
    const stored = (await host.storage.get(INTENT_KEY)) || {};
    sign = typeof stored.sign === "boolean" ? stored.sign : !!settings().signByDefault;
    encrypt = typeof stored.encrypt === "boolean" ? stored.encrypt : !!settings().encryptByDefault;
    attachKey = !!stored.attachKey;
  }
  return { sign: !!sign, encrypt: !!encrypt, attachKey: !!attachKey };
}

async function onComposeSend(req) {
  if (!req || typeof req !== "object") return undefined;

  const { sign, encrypt } = await resolveIntent(req);
  if (!sign && !encrypt) return undefined; // not our job — host sends normally

  if (!(await isCapable())) {
    host.toast.error("Cannot sign/encrypt: OpenPGP is not running in the privileged tier.");
    return false;
  }

  try {
    const identityId = req.identityId || req.identity || "";
    if (!identityId) throw new Error("No sending identity available");

    const fromEmail = (addrList(req.from)[0] || {}).email || req.fromEmail || "";
    const signingKey = sign ? await firstSigningKey() : null;
    if (sign && !signingKey) {
      host.toast.error("Unlock a personal key in Settings → Plugins → OpenPGP before signing.");
      return false;
    }

    const allRecipientEmails = [...new Set([...emailsOf(req.to), ...emailsOf(req.cc), ...emailsOf(req.bcc)])];
    const envelope = {
      from: formatAddrs(req.from) || fromEmail,
      to: formatAddrs(req.to),
      cc: formatAddrs(req.cc),
      subject: req.subject || "",
      inReplyTo: req.inReplyTo,
      references: Array.isArray(req.references) ? req.references.join(" ") : req.references,
    };
    const plainBody = req.textBody || req.text || req.htmlBody || req.html || "";
    const inline = (settings().messageFormat || "pgpmime") === "inline";

    let part;
    if (inline) {
      if (encrypt) {
        const selfPub = signingKey ? signingKey.toPublic().armor() : await selfPublicForEmail(fromEmail);
        const recipientKeys = await resolveRecipientKeys(allRecipientEmails, selfPub);
        const ciphertext = await engine.encryptText({
          text: plainBody,
          recipientPublicKeysArmored: recipientKeys,
          signingKey,
          algorithm: settings().defaultEncryptionAlgorithm || "aes256",
        });
        part = pgp.buildInline({ armor: ciphertext });
      } else {
        const cleartext = await engine.cleartextSign({ text: plainBody, signingKey });
        part = pgp.buildInline({ armor: cleartext });
      }
    } else {
      const innerPart = pgp.buildTextPart(plainBody);
      if (encrypt) {
        const selfPub = signingKey ? signingKey.toPublic().armor() : await selfPublicForEmail(fromEmail);
        const recipientKeys = await resolveRecipientKeys(allRecipientEmails, selfPub);
        const ciphertext = await engine.encryptText({
          text: innerPart,
          recipientPublicKeysArmored: recipientKeys,
          signingKey,
          algorithm: settings().defaultEncryptionAlgorithm || "aes256",
        });
        part = pgp.buildEncrypted({ armoredCiphertext: ciphertext });
      } else {
        const signature = await engine.detachedSign({ text: innerPart, signingKey });
        part = pgp.buildSigned({ signedPart: innerPart, armoredSignature: signature });
      }
    }

    const raw = pgp.serializeMessage({ ...envelope, ...part });
    await host.jmap.sendRaw(strToArrayBuffer(raw), identityId, { envelopeRecipients: allRecipientEmails });

    host.toast.success(
      encrypt && sign ? "Message signed, encrypted and sent" : encrypt ? "Message encrypted and sent" : "Message signed and sent"
    );
    await host.storage.set(INTENT_KEY, {}); // reset for the next compose
    return false; // we handled the send
  } catch (err) {
    host.log.error("onComposeSend failed", err);
    host.toast.error(`OpenPGP send failed: ${err && err.message ? err.message : String(err)}`);
    return false; // never fall through to a plaintext send when sign/encrypt was requested
  }
}

async function selfPublicForEmail(email) {
  const k = await store.findPublicKeyForEmail(email);
  return k ? k.armored : null;
}

// ─── Render-body takeover (decrypt / verify) ───────────────────────────

async function persistStatus(id, status) {
  if (!id) return;
  try {
    await host.storage.set(VERIFY_PREFIX + id, status);
  } catch {
    /* ignore */
  }
}

function noticeHtml(message, tone) {
  const color =
    tone === "error" ? "var(--color-destructive, #dc2626)" : tone === "ok" ? "var(--color-success, #16a34a)" : "var(--color-muted-foreground, #64748b)";
  return `<div style="padding:12px;border:1px solid ${color};border-radius:8px;color:${color};font-size:14px;">${message}</div>`;
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function bodyHtml(text) {
  return `<div style="white-space:pre-wrap;font-family:inherit">${escapeHtml(text)}</div>`;
}

function signerEmailFor(keyID, publicRecords) {
  if (!keyID) return null;
  const wanted = keyID.toLowerCase();
  const match = publicRecords.find((r) => {
    const id = (r.keyID || "").toLowerCase();
    return id && (id.endsWith(wanted) || wanted.endsWith(id));
  });
  return match ? (match.userIDs[0] || {}).email || null : null;
}

async function maybeAutoImport(text) {
  if (settings().autoImportSignerKeys === false) return;
  if (!pgp.containsPublicKeyBlock(text)) return;
  try {
    const meta = await engine.inspectKey(pgp.extractPublicKeyBlock(text));
    if (!meta.isPrivate) await store.savePublicKey(meta);
  } catch {
    /* ignore bad embedded keys */
  }
}

async function onRenderEmailBody(body, ctx) {
  if (!ctx) return undefined;
  if (!(await isCapable())) return undefined;

  let raw;
  try {
    const blobId = ctx.blobId || ctx.id;
    if (!blobId) return undefined;
    raw = new TextDecoder("utf-8", { fatal: false }).decode(await toBytes(await host.jmap.fetchBlob(blobId)));
  } catch (err) {
    host.log.warn("fetchBlob failed", err);
    return undefined;
  }

  const info = pgp.detect(raw);
  if (info.kind === "none") return undefined; // not a PGP message — host renders it

  const publicRecords = await store.listPublicKeys();
  const verificationKeys = publicRecords.map((k) => k.armored);
  const status = { isEncrypted: false, decrypted: false, signatureStatus: "none", signerEmail: null };

  try {
    if (info.kind === "pgp-mime-encrypted" || info.kind === "inline-encrypted") {
      status.isEncrypted = true;
      const decKeys = await unlockedPrivateKeys();
      if (decKeys.length === 0) {
        await persistStatus(ctx.id, { ...status, decryptionError: "locked" });
        return { ...body, handledBy: "openpgp", html: noticeHtml("🔒 This message is encrypted. Unlock your OpenPGP key in Settings to read it.", "muted"), text: "Encrypted — unlock your key to read.", attachments: [], verification: { ...status, decryptionError: "locked" } };
      }
      const dec = await engine.decryptText({ armoredMessage: info.ciphertext, decryptionKeys: decKeys, verificationKeysArmored: verificationKeys });
      status.decrypted = true;
      applySig(status, dec.signature, publicRecords);
      await maybeAutoImport(dec.text);
      await persistStatus(ctx.id, status);
      const rb = renderBody(dec.text);
      return { ...body, handledBy: "openpgp", html: rb.html, text: rb.text, attachments: rb.attachments, verification: status };
    }

    if (info.kind === "pgp-mime-signed") {
      const sig = await engine.verifyDetached({ text: info.signedBytes, armoredSignature: info.signature, verificationKeysArmored: verificationKeys });
      applySig(status, sig, publicRecords);
      await persistStatus(ctx.id, status);
      const rb = renderBody(info.signedBytes);
      return { ...body, handledBy: "openpgp", html: rb.html, text: rb.text, attachments: rb.attachments, verification: status };
    }

    if (info.kind === "inline-signed") {
      const v = await engine.verifyCleartext({ cleartext: info.cleartext, verificationKeysArmored: verificationKeys });
      applySig(status, v.signature, publicRecords);
      await maybeAutoImport(v.text);
      await persistStatus(ctx.id, status);
      const rb = renderBody(v.text);
      return { ...body, handledBy: "openpgp", html: rb.html, text: rb.text, attachments: rb.attachments, verification: status };
    }
  } catch (err) {
    host.log.error("onRenderEmailBody failed", err);
    const errStatus = { ...status, error: err && err.message ? err.message : String(err) };
    await persistStatus(ctx.id, errStatus);
    return { ...body, handledBy: "openpgp", html: noticeHtml(`OpenPGP error: ${escapeHtml(errStatus.error)}`, "error"), text: errStatus.error, attachments: [], verification: errStatus };
  }

  return undefined;
}

function applySig(status, sig, publicRecords) {
  if (!sig || sig.status === "none") {
    status.signatureStatus = "none";
    return;
  }
  status.signatureStatus = sig.status;
  status.signerEmail = signerEmailFor(sig.keyID, publicRecords);
}

// Turn a decrypted/verified MIME entity (or plain text) into the body object
// the host renders: prefer the parsed text/html part, fall back to plain text,
// then apply the remote-content / external-link privacy pass.
function renderBody(raw) {
  const r = pgp.renderInnerMime(raw);
  let html = r.html ? r.html : bodyHtml(r.text || "");
  const s = settings();
  const blockRemote = s.blockRemoteContent !== false; // default on
  const disableLinks = !!s.disableExternalLinks; // default off
  const sani = pgp.sanitizeHtml(html, { blockRemoteContent: blockRemote, disableExternalLinks: disableLinks });
  html = sani.html;
  if (blockRemote && sani.blockedRemote > 0) html = remoteBlockedNotice(sani.blockedRemote) + html;
  return { html, text: r.text || "", attachments: r.attachments || [] };
}

function remoteBlockedNotice(n) {
  return (
    `<div style="display:flex;align-items:center;gap:8px;padding:6px 10px;margin:0 0 8px;border-radius:6px;` +
    `font-size:12px;background:var(--color-muted, rgba(100,116,139,0.1));color:var(--color-muted-foreground, #64748b)">` +
    `🛡️ ${n} remote resource${n === 1 ? "" : "s"} blocked for your privacy.</div>`
  );
}

// ═══════════════════════════════════════════════════════════════════════
// UI
// ═══════════════════════════════════════════════════════════════════════

const card = { border: "1px solid var(--color-border, #e2e8f0)", borderRadius: "8px", padding: "12px", background: "var(--color-card, #fff)", color: "var(--color-foreground, #0f172a)" };
const btn = { font: "inherit", padding: "6px 12px", borderRadius: "6px", border: "1px solid var(--color-input, #cbd5e1)", background: "var(--color-muted, #f1f5f9)", color: "var(--color-foreground, #0f172a)", cursor: "pointer" };
const btnPrimary = { ...btn, background: "var(--color-primary, #2563eb)", color: "#fff", border: "1px solid var(--color-primary, #2563eb)" };
const btnDanger = { ...btn, color: "var(--color-destructive, #dc2626)", borderColor: "var(--color-destructive, #dc2626)" };
const input = { font: "inherit", padding: "6px 8px", borderRadius: "6px", border: "1px solid var(--color-input, #cbd5e1)", background: "var(--color-background, #fff)", color: "var(--color-foreground, #0f172a)", width: "100%", boxSizing: "border-box" };
const muted = { fontSize: "12px", color: "var(--color-muted-foreground, #64748b)" };

function fmtFp(fp) {
  return (fp || "").toUpperCase().replace(/(.{4})/g, "$1 ").trim();
}

// ─── composer-toolbar slot ─────────────────────────────────────────────

function ComposerToolbar() {
  const [intent, setIntent] = useState({ sign: false, encrypt: false, attachKey: false });
  const [ready, setReady] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        if (!(await isCapable())) return setReady(false);
        const stored = (await host.storage.get(INTENT_KEY)) || {};
        setIntent({
          sign: typeof stored.sign === "boolean" ? stored.sign : !!settings().signByDefault,
          encrypt: typeof stored.encrypt === "boolean" ? stored.encrypt : !!settings().encryptByDefault,
          attachKey: !!stored.attachKey,
        });
        setReady((await store.listPrivateKeys()).length > 0 || (await store.listPublicKeys()).length > 0);
      } catch {
        setReady(false);
      }
    })();
  }, []);

  const update = useCallback(async (next) => {
    setIntent(next);
    await host.storage.set(INTENT_KEY, next);
  }, []);
  const toggle = (key) => update({ ...intent, [key]: !intent[key] });

  const attachMyKey = async () => {
    try {
      const privs = await store.listPrivateKeys();
      if (privs.length === 0) throw new Error("Generate or import a personal key first.");
      const chosen = (await firstUnlockedRecord(privs)) || privs[0];
      const pub = await store.listPublicKeys().then((ks) => ks.find((k) => k.fingerprint === chosen.fingerprint));
      if (!pub) throw new Error("Public key not found for your key.");
      await navigator.clipboard.writeText(pub.armored);
      host.toast.success("Your public key was copied — paste it into the message to share it.");
    } catch (err) {
      host.toast.error(err.message || String(err));
    }
  };

  const pill = (active) => ({ ...btn, background: active ? "var(--color-primary, #2563eb)" : "var(--color-muted, #f1f5f9)", color: active ? "#fff" : "var(--color-foreground, #0f172a)", border: active ? "1px solid var(--color-primary, #2563eb)" : "1px solid var(--color-input, #cbd5e1)" });

  if (!ready) {
    return h("span", { style: muted }, "OpenPGP: add a key in Settings to sign/encrypt");
  }
  return h(
    "div",
    { style: { display: "inline-flex", gap: "6px", alignItems: "center" } },
    h("button", { type: "button", style: pill(intent.sign), title: "Digitally sign this message", onClick: () => toggle("sign") }, intent.sign ? "✓ Sign" : "Sign"),
    h("button", { type: "button", style: pill(intent.encrypt), title: "Encrypt this message to its recipients", onClick: () => toggle("encrypt") }, intent.encrypt ? "✓ Encrypt" : "Encrypt"),
    h("button", { type: "button", style: btn, title: "Copy your public key to share", onClick: attachMyKey }, "Attach my key")
  );
}

async function firstUnlockedRecord(records) {
  for (const r of records) if (await store.isUnlocked(r.fingerprint)) return r;
  return null;
}

// Unwrap a stored private key with the at-rest passphrase and put the decrypted
// secret key into the shared session store. Shared by the full key manager
// (settings) and the lean sidebar unlock panel so the fiddly at-rest-vs-PGP
// passphrase handling lives in exactly one place. Throws a user-facing message.
async function unlockKeyToSession(rec, pass) {
  if (!pass) throw new Error("Enter the passphrase.");
  let armored;
  try {
    armored = await store.revealPrivateKeyArmored(rec.fingerprint, pass);
  } catch {
    throw new Error("Wrong at-rest passphrase (could not unwrap the stored key).");
  }
  let key;
  try {
    key = await engine.unlockPrivateKey(armored, pass); // same pass also protects the PGP key
  } catch {
    try {
      key = await engine.unlockPrivateKey(armored, ""); // key has no PGP passphrase
    } catch {
      throw new Error("Unwrapped OK, but the secret key has a different PGP passphrase. Re-import it using that same passphrase in the at-rest field.");
    }
  }
  await store.rememberSessionKey(rec.fingerprint, key.armor());
}

// ─── email-banner slot ─────────────────────────────────────────────────

function EmailBanner(props) {
  const email = props && props.email;
  const [status, setStatus] = useState(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let alive = true;
    (async () => {
      if (!email || !email.id) {
        setLoaded(true);
        return;
      }
      const s = await host.storage.get(VERIFY_PREFIX + email.id);
      if (alive) {
        setStatus(s || null);
        setLoaded(true);
      }
    })();
    return () => {
      alive = false;
    };
  }, [email && email.id]);

  if (!loaded || !status) return null;

  const tone = (t) => (t === "ok" ? "var(--color-success, #16a34a)" : t === "error" ? "var(--color-destructive, #dc2626)" : t === "warn" ? "var(--color-warning, #d97706)" : "var(--color-muted-foreground, #64748b)");
  const rows = [];
  if (status.isEncrypted) {
    if (status.decrypted) rows.push(["🔓", "Decrypted", "ok"]);
    else if (status.decryptionError === "locked") rows.push(["🔒", "Encrypted — unlock your key to read", "warn"]);
    else rows.push(["🔒", "Encrypted message", "muted"]);
  }
  if (status.signatureStatus === "valid") rows.push(["🛡️", `Signature valid${status.signerEmail ? " — " + status.signerEmail : ""}`, "ok"]);
  else if (status.signatureStatus === "invalid") rows.push(["⚠️", "Signature INVALID", "error"]);
  else if (status.signatureStatus === "unknown") rows.push(["✍️", "Signed by an unknown key", settings().warnOnUnverifiedSender === false ? "muted" : "warn"]);
  if (status.error) rows.push(["⚠️", status.error, "error"]);
  if (rows.length === 0) return null;

  return h(
    "div",
    { style: { display: "flex", flexDirection: "column", gap: "4px", margin: "4px 0" } },
    rows.map(([icon, text, t], i) =>
      h("div", { key: i, style: { display: "flex", gap: "8px", alignItems: "center", padding: "6px 10px", borderRadius: "6px", fontSize: "13px", border: `1px solid ${tone(t)}`, color: tone(t), background: "var(--color-muted, rgba(100,116,139,0.06))" } }, h("span", null, icon), h("span", null, text))
    )
  );
}

// ─── keyserver lookup (keys.openpgp.org) ───────────────────────────────

function keyserverUrl() {
  return settings().keyserverUrl || "https://keys.openpgp.org";
}

// A deterministic colour "barcode" derived from the fingerprint bytes: one
// swatch per byte, hue mapped from the byte value. It gives a fingerprint a
// distinctive gestalt so a human can spot at a glance whether two fingerprints
// differ — a faster first-pass than reading 40 hex characters. It is only an
// aid; the grouped hex below it remains the authoritative value to compare.
function VisualFingerprint({ fingerprint }) {
  const hex = (fingerprint || "").replace(/[^0-9a-fA-F]/g, "").toUpperCase();
  const bytes = hex.match(/.{1,2}/g) || [];
  return h(
    "div",
    { style: { display: "flex", gap: "3px", flexWrap: "wrap", margin: "6px 0" }, title: "Visual fingerprint — compare this pattern with the one the key's owner shows you", "aria-hidden": "true" },
    bytes.map((b, i) => {
      const n = parseInt(b, 16);
      const hue = Math.round((n / 256) * 360);
      return h("span", { key: i, style: { width: "15px", height: "15px", borderRadius: "3px", background: `hsl(${hue} 62% 52%)`, boxShadow: "inset 0 0 0 1px rgba(0,0,0,0.18)" } });
    })
  );
}

// Look up a public key on keys.openpgp.org, verify the returned key actually
// carries the requested fingerprint, let the user visually confirm it, then
// import it into the recipient keyring.
function KeyLookupPanel({ onImported }) {
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [result, setResult] = useState(null); // { meta, kind, requested, matched }
  const [imported, setImported] = useState(false);

  const reset = () => {
    setResult(null);
    setErr("");
    setImported(false);
  };

  const doLookup = async () => {
    setBusy(true);
    reset();
    try {
      const { query: q, armored } = await keyserver.lookup(query, { baseUrl: keyserverUrl() });
      if (!armored) {
        setErr(q.kind === "email" ? "No key is published for that email address." : "No key with that fingerprint is on the keyserver.");
        return;
      }
      const meta = await engine.inspectKey(armored);
      const actual = (meta.fingerprint || "").toUpperCase();
      let matched = null; // null = nothing to check against (email lookup)
      if (q.kind === "fingerprint") matched = actual === q.value;
      else if (q.kind === "keyid") matched = actual.endsWith(q.value);
      if (matched === false) {
        // The keyserver returned a key that is NOT the one we asked for. Never
        // trust it — a keyserver must not be able to substitute a key.
        setErr(`The keyserver returned a key whose fingerprint (${fmtFp(actual)}) does not match what you asked for. It was rejected.`);
        return;
      }
      setResult({ meta, kind: q.kind, requested: q.value, matched });
    } catch (e) {
      setErr(e && e.message ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const doImport = async () => {
    if (!result) return;
    setBusy(true);
    try {
      await store.savePublicKey(result.meta);
      setImported(true);
      host.toast.success("Public key imported to your recipient keyring.");
      if (onImported) await onImported();
    } catch (e) {
      setErr(e && e.message ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const onKeyDown = (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      if (query.trim() && !busy) doLookup();
    }
  };

  return h(
    "div",
    { style: { ...card, display: "flex", flexDirection: "column", gap: "8px", marginBottom: "8px" } },
    h("div", { style: { display: "flex", gap: "6px", flexWrap: "wrap" } }, h("input", { style: { ...input, flex: "1 1 220px", width: "auto", fontFamily: "monospace" }, placeholder: "Fingerprint or email", value: query, onChange: (e) => setQuery(e.target.value), onKeyDown }), h("button", { type: "button", style: btnPrimary, disabled: busy || !query.trim(), onClick: doLookup }, busy && !result ? "Searching…" : "Look up")),
    h("div", { style: muted }, "Searches ", h("span", { style: { fontFamily: "monospace" } }, keyserverUrl().replace(/^https?:\/\//, "")), ". Email lookups only return keys whose owner verified that address."),
    err ? h("div", { style: { color: "var(--color-destructive, #dc2626)", fontSize: "13px", lineHeight: 1.4 } }, err) : null,
    result ? h(KeyLookupResult, { result, imported, busy, onImport: doImport, onDismiss: reset }) : null
  );
}

function KeyLookupResult({ result, imported, busy, onImport, onDismiss }) {
  const { meta, kind, matched } = result;
  const okColor = "var(--color-success, #16a34a)";
  const warnColor = "var(--color-warning, #d97706)";

  // The trust banner: an exact fingerprint match is machine-verified; an email
  // lookup is not, so the user must confirm the fingerprint out-of-band.
  const banner =
    matched === true
      ? h("div", { style: { color: okColor, fontSize: "13px", fontWeight: 600 } }, "✓ Verified — the key on the server has exactly the fingerprint you asked for.")
      : h("div", { style: { color: warnColor, fontSize: "13px", fontWeight: 600, lineHeight: 1.4 } }, kind === "email" ? "Confirm this fingerprint out-of-band (in person, phone, Signal…) before you trust this key." : "Compare this fingerprint against a trusted copy before you trust this key.");

  return h(
    "div",
    { style: { border: `1px solid ${matched === true ? okColor : warnColor}`, borderRadius: "8px", padding: "10px", display: "flex", flexDirection: "column", gap: "4px" } },
    banner,
    h(
      "div",
      { style: { marginTop: "4px" } },
      meta.userIDs.length === 0
        ? h("div", { style: muted }, "(no user IDs on this key)")
        : meta.userIDs.map((u, i) => h("div", { key: i, style: { fontWeight: 600, fontSize: "14px" } }, u.name ? `${u.name} <${u.email}>` : u.email))
    ),
    h("div", { style: { ...muted } }, `${meta.algorithm} · created ${(meta.created || "").slice(0, 10)}${meta.expiration ? ` · expires ${meta.expiration.slice(0, 10)}` : ""}`),
    h(VisualFingerprint, { fingerprint: meta.fingerprint }),
    h("div", { style: { fontFamily: "monospace", fontSize: "13px", letterSpacing: "0.5px", wordBreak: "break-all" } }, fmtFp(meta.fingerprint)),
    h(
      "div",
      { style: { display: "flex", gap: "6px", marginTop: "6px", flexWrap: "wrap" } },
      imported ? h("span", { style: { color: okColor, fontSize: "13px", alignSelf: "center" } }, "✓ Imported") : h("button", { type: "button", style: btnPrimary, disabled: busy, onClick: onImport }, "Import this key"),
      h("button", { type: "button", style: btn, disabled: busy, onClick: onDismiss }, imported ? "Close" : "Cancel")
    )
  );
}

// ─── settings-section slot (key manager) ───────────────────────────────

function SettingsSection() {
  const [privs, setPrivs] = useState([]);
  const [pubs, setPubs] = useState([]);
  const [unlocked, setUnlocked] = useState({});
  const [busy, setBusy] = useState(false);
  const [capable, setCapable] = useState(true);

  // generate form
  const [gen, setGen] = useState({ open: false, name: "", email: "", pass: "" });
  // import form
  const [imp, setImp] = useState({ open: false, text: "", pass: "" });
  // keyserver lookup panel
  const [lookupOpen, setLookupOpen] = useState(false);
  // inline unlock form (sandboxed iframes block window.prompt, so unlock is inline)
  const [unlocking, setUnlocking] = useState({ fingerprint: null, pass: "" });

  const refresh = useCallback(async () => {
    if (!(await isCapable())) return setCapable(false);
    const [k, p] = await Promise.all([store.listPrivateKeys(), store.listPublicKeys()]);
    setPrivs(k);
    setPubs(p);
    const u = {};
    for (const r of k) u[r.fingerprint] = await store.isUnlocked(r.fingerprint);
    setUnlocked(u);
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const run = async (fn) => {
    setBusy(true);
    try {
      await fn();
      await refresh();
    } catch (err) {
      host.toast.error(err && err.message ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  if (!capable) {
    return h("div", { style: { ...card, borderColor: "var(--color-destructive, #dc2626)", color: "var(--color-destructive, #dc2626)", maxWidth: "720px" } }, h("div", { style: { fontWeight: 600, marginBottom: "6px" } }, "OpenPGP is not active"), h("div", { style: { fontSize: "13px", lineHeight: 1.5 } }, NOT_PRIVILEGED_MSG));
  }

  const doGenerate = () =>
    run(async () => {
      const kp = await engine.generateKeyPair({ name: gen.name, email: gen.email, passphrase: gen.pass, keyType: settings().newKeyType || "ecc" });
      const meta = await engine.inspectKey(kp.privateKeyArmored);
      await store.savePrivateKey(meta, kp.privateKeyArmored, gen.pass || meta.fingerprint);
      host.toast.success("Key pair generated.");
      setGen({ open: false, name: "", email: "", pass: "" });
    });

  const doImport = () =>
    run(async () => {
      const meta = await engine.inspectKey(imp.text.trim());
      if (meta.isPrivate) {
        if (!imp.pass) throw new Error("Set an at-rest passphrase to store a private key.");
        await store.savePrivateKey(meta, imp.text.trim(), imp.pass);
        host.toast.success("Private key imported.");
      } else {
        await store.savePublicKey(meta);
        host.toast.success("Public key imported.");
      }
      setImp({ open: false, text: "", pass: "" });
    });

  const copyPublic = (fp) =>
    run(async () => {
      const k = pubs.find((x) => x.fingerprint === fp);
      if (k) {
        await navigator.clipboard.writeText(k.armored);
        host.toast.success("Public key copied to clipboard.");
      }
    });

  // Publish a personal public key to keys.openpgp.org so others can find it,
  // and trigger the address-verification email that makes it searchable by
  // address. Uploading is outward-facing and hard to undo, so confirm first.
  const publishKey = (fp) =>
    run(async () => {
      const k = pubs.find((x) => x.fingerprint === fp);
      if (!k) throw new Error("Public key not found.");
      const emails = (k.userIDs || []).map((u) => u.email).filter(Boolean);
      const ok = await host.ui.confirm({
        title: "Publish public key",
        message: `Upload your PUBLIC key${emails.length ? ` for ${emails.join(", ")}` : ""} to ${keyserverUrl()} so others can find it? Your secret key is never uploaded. Keys on a keyserver are hard to remove.`,
        confirmLabel: "Publish",
      });
      if (!ok) return;
      const res = await keyserver.uploadKey(k.armored, { baseUrl: keyserverUrl() });
      const status = res.status || {};
      const addrs = Object.keys(status);
      const needVerify = addrs.filter((a) => status[a] !== "published" && status[a] !== "revoked");
      if (res.token && needVerify.length) {
        await keyserver.requestVerify(res.token, needVerify, { baseUrl: keyserverUrl() });
        host.toast.success(`Uploaded. Check ${needVerify.join(", ")} for a confirmation email — until you click it, the key is on the server but not searchable by address.`);
      } else if (addrs.some((a) => status[a] === "published")) {
        host.toast.success("Uploaded — this address is already verified and searchable.");
      } else {
        host.toast.success("Public key uploaded to the keyserver.");
      }
    });

  const doUnlock = async (rec) => {
    setBusy(true);
    setUnlocking((u) => ({ ...u, err: "" }));
    try {
      await unlockKeyToSession(rec, unlocking.pass);
      setUnlocking({ fingerprint: null, pass: "", err: "" });
      host.toast.success("Key unlocked for this session.");
      await refresh();
    } catch (err) {
      const msg = err && err.message ? err.message : String(err);
      setUnlocking((u) => ({ ...u, err: msg }));
      host.toast.error(msg);
    } finally {
      setBusy(false);
    }
  };

  const lockKey = (rec) => run(async () => store.forgetSessionKey(rec.fingerprint));

  const deletePriv = (rec) =>
    run(async () => {
      const ok = await host.ui.confirm({ title: "Delete private key", message: "Delete this private key permanently? You will no longer be able to decrypt mail encrypted to it.", danger: true, confirmLabel: "Delete" });
      if (!ok) return;
      await store.deletePrivateKey(rec.fingerprint);
      host.toast.success("Private key deleted.");
    });

  const deletePub = (rec) => run(async () => store.deletePublicKey(rec.fingerprint));

  return h(
    "div",
    { style: { display: "flex", flexDirection: "column", gap: "16px", maxWidth: "720px" } },
    // ----- your keys -----
    h(
      "div",
      null,
      h("h3", { style: { margin: "0 0 4px", fontSize: "15px", fontWeight: 600 } }, "Your keys"),
      h("p", { style: { ...muted, margin: "0 0 8px" } }, "Generate a new key pair or import an existing armored key. Secret keys are encrypted in your browser and never leave it."),
      h(
        "div",
        { style: { display: "flex", gap: "8px", marginBottom: "8px", flexWrap: "wrap" } },
        h("button", { type: "button", style: btnPrimary, disabled: busy, onClick: () => setGen((g) => ({ ...g, open: !g.open })) }, "Generate key pair"),
        h("button", { type: "button", style: btn, disabled: busy, onClick: () => setImp((i) => ({ ...i, open: !i.open })) }, "Import key")
      ),
      gen.open
        ? h(
            "div",
            { style: { ...card, display: "flex", flexDirection: "column", gap: "8px", marginBottom: "8px" } },
            h("input", { style: input, placeholder: "Name (optional)", value: gen.name, onChange: (e) => setGen({ ...gen, name: e.target.value }) }),
            h("input", { style: input, placeholder: "Email", value: gen.email, onChange: (e) => setGen({ ...gen, email: e.target.value }) }),
            h("input", { style: input, type: "password", placeholder: "Passphrase (protects the secret key)", value: gen.pass, onChange: (e) => setGen({ ...gen, pass: e.target.value }) }),
            h("button", { type: "button", style: btnPrimary, disabled: busy, onClick: doGenerate }, "Generate")
          )
        : null,
      imp.open
        ? h(
            "div",
            { style: { ...card, display: "flex", flexDirection: "column", gap: "8px", marginBottom: "8px" } },
            h("textarea", { style: { ...input, fontFamily: "monospace", fontSize: "12px" }, rows: 6, placeholder: "-----BEGIN PGP PUBLIC KEY BLOCK----- … or a PRIVATE KEY block", value: imp.text, onChange: (e) => setImp({ ...imp, text: e.target.value }) }),
            h("input", { style: input, type: "password", placeholder: "At-rest passphrase (private keys only)", value: imp.pass, onChange: (e) => setImp({ ...imp, pass: e.target.value }) }),
            h("button", { type: "button", style: btnPrimary, disabled: busy, onClick: doImport }, "Import")
          )
        : null,
      privs.length === 0
        ? h("div", { style: { ...card, ...muted } }, "No personal keys yet.")
        : h(
            "div",
            { style: { display: "flex", flexDirection: "column", gap: "8px" } },
            privs.map((rec) => {
              const uid = rec.userIDs[0] || {};
              const isUnlocking = unlocking.fingerprint === rec.fingerprint;
              return h(
                "div",
                { key: rec.fingerprint, style: card },
                h(
                  "div",
                  { style: { display: "flex", justifyContent: "space-between", gap: "8px", flexWrap: "wrap" } },
                  h(
                    "div",
                    null,
                    h("div", { style: { fontWeight: 600, fontSize: "14px" } }, `${uid.name || ""} <${uid.email || "?"}>`),
                    h("div", { style: { ...muted, fontFamily: "monospace" } }, `${rec.algorithm} · ${fmtFp(rec.fingerprint)}`)
                  ),
                  h(
                    "div",
                    { style: { display: "flex", gap: "6px", flexWrap: "wrap" } },
                    unlocked[rec.fingerprint]
                      ? h("button", { type: "button", style: btn, disabled: busy, onClick: () => lockKey(rec) }, "🔓 Lock")
                      : h("button", { type: "button", style: btnPrimary, disabled: busy, onClick: () => setUnlocking(isUnlocking ? { fingerprint: null, pass: "", err: "" } : { fingerprint: rec.fingerprint, pass: "", err: "" }) }, "🔒 Unlock"),
                    h("button", { type: "button", style: btn, disabled: busy, onClick: () => copyPublic(rec.fingerprint) }, "Copy public key"),
                    settings().enableKeyserverLookup === false ? null : h("button", { type: "button", style: btn, disabled: busy, onClick: () => publishKey(rec.fingerprint) }, "Publish"),
                    h("button", { type: "button", style: btnDanger, disabled: busy, onClick: () => deletePriv(rec) }, "Delete")
                  )
                ),
                isUnlocking && !unlocked[rec.fingerprint]
                  ? h(
                      "div",
                      { style: { marginTop: "8px" } },
                      h(
                        "div",
                        { style: { display: "flex", gap: "6px", flexWrap: "wrap" } },
                        h("input", {
                          style: { ...input, flex: "1 1 180px", width: "auto" },
                          type: "password",
                          autoFocus: true,
                          placeholder: "At-rest passphrase",
                          value: unlocking.pass,
                          onChange: (e) => setUnlocking({ fingerprint: rec.fingerprint, pass: e.target.value, err: unlocking.err }),
                          onKeyDown: (e) => {
                            if (e.key === "Enter") {
                              e.preventDefault();
                              doUnlock(rec);
                            }
                          },
                        }),
                        h("button", { type: "button", style: btnPrimary, disabled: busy || !unlocking.pass, onClick: () => doUnlock(rec) }, busy ? "Unlocking…" : "Confirm"),
                        h("button", { type: "button", style: btn, disabled: busy, onClick: () => setUnlocking({ fingerprint: null, pass: "", err: "" }) }, "Cancel")
                      ),
                      unlocking.err ? h("div", { style: { color: "var(--color-destructive, #dc2626)", fontSize: "12px", marginTop: "6px" } }, unlocking.err) : null
                    )
                  : null
              );
            })
          )
    ),
    // ----- recipient keys -----
    h(
      "div",
      null,
      h("h3", { style: { margin: "0 0 4px", fontSize: "15px", fontWeight: 600 } }, "Recipient keys"),
      h("p", { style: { ...muted, margin: "0 0 8px" } }, "Public keys of people you send encrypted mail to. Keys embedded in validly signed mail are saved automatically."),
      settings().enableKeyserverLookup === false
        ? null
        : h(
            "div",
            { style: { marginBottom: "8px" } },
            h("button", { type: "button", style: btn, disabled: busy, onClick: () => setLookupOpen((v) => !v) }, lookupOpen ? "Close keyserver lookup" : "🔍 Find a key on keys.openpgp.org"),
            lookupOpen ? h("div", { style: { marginTop: "8px" } }, h(KeyLookupPanel, { onImported: refresh })) : null
          ),
      pubs.length === 0
        ? h("div", { style: { ...card, ...muted } }, "No recipient keys stored.")
        : h(
            "div",
            { style: { display: "flex", flexDirection: "column", gap: "6px" } },
            pubs.map((rec) => {
              const uid = rec.userIDs[0] || {};
              return h(
                "div",
                { key: rec.fingerprint, style: { ...card, display: "flex", justifyContent: "space-between", gap: "8px", alignItems: "center", flexWrap: "wrap" } },
                h("div", null, h("div", { style: { fontWeight: 600, fontSize: "13px" } }, `${uid.name || ""} <${uid.email || "?"}>`), h("div", { style: { ...muted, fontFamily: "monospace" } }, fmtFp(rec.fingerprint))),
                h("div", { style: { display: "flex", gap: "6px" } }, h("button", { type: "button", style: btn, disabled: busy, onClick: () => copyPublic(rec.fingerprint) }, "Copy"), h("button", { type: "button", style: btnDanger, disabled: busy, onClick: () => deletePub(rec) }, "Remove"))
              );
            })
          )
    )
  );
}

// ─── sidebar-widget slot (lean per-session unlock) ─────────────────────
// The full key manager (generate / import / recipients / keyserver lookup)
// lives in the settings-section slot, under Settings → Plugins → OpenPGP.
// On the mail view we only expose the one action you need while reading and
// composing: unlock/lock your personal keys for the current session.

function SidebarUnlock() {
  const [privs, setPrivs] = useState([]);
  const [unlocked, setUnlocked] = useState({});
  const [busy, setBusy] = useState(false);
  const [capable, setCapable] = useState(true);
  const [unlocking, setUnlocking] = useState({ fingerprint: null, pass: "", err: "" });

  const refresh = useCallback(async () => {
    if (!(await isCapable())) return setCapable(false);
    const k = await store.listPrivateKeys();
    setPrivs(k);
    const u = {};
    for (const r of k) u[r.fingerprint] = await store.isUnlocked(r.fingerprint);
    setUnlocked(u);
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const doUnlock = async (rec) => {
    setBusy(true);
    setUnlocking((u) => ({ ...u, err: "" }));
    try {
      await unlockKeyToSession(rec, unlocking.pass);
      setUnlocking({ fingerprint: null, pass: "", err: "" });
      host.toast.success("Key unlocked for this session.");
      await refresh();
    } catch (err) {
      const msg = err && err.message ? err.message : String(err);
      setUnlocking((u) => ({ ...u, err: msg }));
      host.toast.error(msg);
    } finally {
      setBusy(false);
    }
  };

  const lockKey = async (rec) => {
    setBusy(true);
    try {
      await store.forgetSessionKey(rec.fingerprint);
      await refresh();
    } catch (err) {
      host.toast.error(err && err.message ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  if (!capable) return null;

  return h(
    "div",
    { style: { padding: "8px 4px" } },
    h("div", { style: { fontWeight: 600, fontSize: "13px", marginBottom: "8px", display: "flex", alignItems: "center", gap: "6px" } }, h("span", null, "🔑"), h("span", null, "OpenPGP keys")),
    privs.length === 0
      ? h("div", { style: { ...card, ...muted } }, "No personal keys yet. Add one in Settings → Plugins → OpenPGP.")
      : h(
          "div",
          { style: { display: "flex", flexDirection: "column", gap: "8px" } },
          privs.map((rec) => {
            const uid = rec.userIDs[0] || {};
            const isUnlocking = unlocking.fingerprint === rec.fingerprint;
            const isUnlocked = unlocked[rec.fingerprint];
            return h(
              "div",
              { key: rec.fingerprint, style: card },
              h("div", { style: { fontWeight: 600, fontSize: "13px", wordBreak: "break-word" } }, `${uid.name || ""} ${uid.email ? "<" + uid.email + ">" : ""}`.trim() || "(key)"),
              h("div", { style: { ...muted, margin: "4px 0 8px" } }, isUnlocked ? h("span", { style: { color: "var(--color-success, #16a34a)" } }, "🔓 Unlocked for this session") : "🔒 Locked"),
              isUnlocked
                ? h("button", { type: "button", style: btn, disabled: busy, onClick: () => lockKey(rec) }, "Lock")
                : isUnlocking
                ? h(
                    "div",
                    { style: { display: "flex", flexDirection: "column", gap: "6px" } },
                    h("input", {
                      style: input,
                      type: "password",
                      autoFocus: true,
                      placeholder: "At-rest passphrase",
                      value: unlocking.pass,
                      onChange: (e) => setUnlocking({ fingerprint: rec.fingerprint, pass: e.target.value, err: unlocking.err }),
                      onKeyDown: (e) => {
                        if (e.key === "Enter") {
                          e.preventDefault();
                          doUnlock(rec);
                        }
                      },
                    }),
                    h(
                      "div",
                      { style: { display: "flex", gap: "6px" } },
                      h("button", { type: "button", style: btnPrimary, disabled: busy || !unlocking.pass, onClick: () => doUnlock(rec) }, busy ? "Unlocking…" : "Confirm"),
                      h("button", { type: "button", style: btn, disabled: busy, onClick: () => setUnlocking({ fingerprint: null, pass: "", err: "" }) }, "Cancel")
                    ),
                    unlocking.err ? h("div", { style: { color: "var(--color-destructive, #dc2626)", fontSize: "12px" } }, unlocking.err) : null
                  )
                : h("button", { type: "button", style: btnPrimary, disabled: busy, onClick: () => setUnlocking({ fingerprint: rec.fingerprint, pass: "", err: "" }) }, "🔒 Unlock")
            );
          })
        ),
    h("div", { style: { ...muted, marginTop: "10px" } }, "Manage keys, recipients and keyserver lookups in Settings → Plugins → OpenPGP.")
  );
}

// ═══════════════════════════════════════════════════════════════════════
// Exports
// ═══════════════════════════════════════════════════════════════════════

export const hooks = {
  onComposeSend,
  onRenderEmailBody,
  async onAfterLogout() {
    if (settings().lockOnLogout === false) return;
    try {
      await store.wipeSessionKeys();
    } catch (err) {
      host.log.warn("wipeSessionKeys failed", err);
    }
  },
  async onAccountSwitch() {
    if (settings().lockOnLogout === false) return;
    try {
      await store.wipeSessionKeys();
    } catch (err) {
      host.log.warn("wipeSessionKeys failed", err);
    }
  },
};

export const slots = {
  "composer-toolbar": { component: ComposerToolbar, order: 70 },
  "email-banner": { component: EmailBanner, order: 20 },
  "settings-section": { component: SettingsSection, order: 100 },
  // Lean mail-view widget: unlock/lock personal keys for the session only.
  // Full key management lives in the settings-section slot.
  "sidebar-widget": { component: SidebarUnlock, order: 60 },
};

export async function activate(api) {
  if (!(await isCapable())) {
    api.log.error(NOT_PRIVILEGED_MSG);
    try {
      api.toast.error("OpenPGP needs the privileged tier — see plugin logs / contact your admin.");
    } catch {
      /* ignore */
    }
    return;
  }
  // Session-scope unlocked keys: clear any left over from a previous app session.
  try {
    await store.wipeSessionKeys();
  } catch (err) {
    api.log.warn("OpenPGP: wipeSessionKeys failed", err);
  }
  let count = 0;
  try {
    count = (await store.listPrivateKeys()).length;
  } catch (err) {
    api.log.warn("OpenPGP: listPrivateKeys failed", err);
  }
  api.log.info(`OpenPGP plugin activated (${count} personal key${count === 1 ? "" : "s"})`);
}
