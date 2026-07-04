// key-storage.js
// Persistent keyring + session store, all backed by IndexedDB so they are
// shared across the plugin's same-origin iframes (the background hook iframe
// and the slot UI iframes are *separate* documents).
//
//  - Public keys (yours + recipients') are stored as plain armored text.
//  - Private keys are stored wrapped: the armored secret key is encrypted with
//    AES-256-GCM under a PBKDF2(SHA-256, 600k) key derived from an unlock
//    passphrase. The cleartext secret key never touches disk.
//  - "Unlocked" keys: the DECRYPTED armored secret key is held in a separate
//    session store so every iframe can use it. It is wiped on app boot and on
//    logout/account-switch, mirroring an in-memory unlock that clears on reload.

const DB_NAME = "bulwark-openpgp";
const DB_VERSION = 2;
const STORE_PRIVATE = "private-keys";
const STORE_PUBLIC = "public-keys";
const STORE_SESSION = "session-keys";

let dbPromise = null;

function openDB() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_PRIVATE)) db.createObjectStore(STORE_PRIVATE, { keyPath: "fingerprint" });
      if (!db.objectStoreNames.contains(STORE_PUBLIC)) db.createObjectStore(STORE_PUBLIC, { keyPath: "fingerprint" });
      if (!db.objectStoreNames.contains(STORE_SESSION)) db.createObjectStore(STORE_SESSION, { keyPath: "fingerprint" });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return dbPromise;
}

function req(store, mode, run) {
  return openDB().then(
    (db) =>
      new Promise((resolve, reject) => {
        const t = db.transaction(store, mode);
        const r = run(t.objectStore(store));
        t.oncomplete = () => resolve(r && r.value !== undefined ? r.value : undefined);
        t.onerror = () => reject(t.error);
        t.onabort = () => reject(t.error);
      })
  );
}

const getAll = (os) => {
  const box = { value: [] };
  os.getAll().onsuccess = (e) => (box.value = e.target.result);
  return box;
};
const getOne = (os, key) => {
  const box = { value: null };
  os.get(key).onsuccess = (e) => (box.value = e.target.result || null);
  return box;
};

// ---------------------------------------------------------------------------
// at-rest wrapping (WebCrypto)
// ---------------------------------------------------------------------------

const enc = new TextEncoder();
const dec = new TextDecoder();

async function deriveWrapKey(passphrase, salt) {
  const base = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function wrap(plaintext, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveWrapKey(passphrase, salt);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext));
  return { salt: b64(salt), iv: b64(iv), ciphertext: b64(new Uint8Array(ct)) };
}

async function unwrap(wrapped, passphrase) {
  const key = await deriveWrapKey(passphrase, fromB64(wrapped.salt));
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(wrapped.iv) }, key, fromB64(wrapped.ciphertext));
  return dec.decode(pt);
}

const b64 = (u8) => btoa(String.fromCharCode(...u8));
const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

// ---------------------------------------------------------------------------
// public keys (recipients + own public halves)
// ---------------------------------------------------------------------------

export function savePublicKey(meta) {
  const record = {
    fingerprint: meta.fingerprint,
    keyID: meta.keyID,
    armored: meta.publicKeyArmored,
    userIDs: meta.userIDs,
    created: meta.created,
    expiration: meta.expiration || null,
    algorithm: meta.algorithm,
  };
  return req(STORE_PUBLIC, "readwrite", (os) => os.put(record)).then(() => record);
}

export function listPublicKeys() {
  return req(STORE_PUBLIC, "readonly", getAll);
}

export function deletePublicKey(fingerprint) {
  return req(STORE_PUBLIC, "readwrite", (os) => os.delete(fingerprint));
}

export async function findPublicKeyForEmail(email) {
  const target = String(email || "").trim().toLowerCase();
  const keys = await listPublicKeys();
  return keys.find((k) => k.userIDs.some((u) => (u.email || "").toLowerCase() === target)) || null;
}

// ---------------------------------------------------------------------------
// private keys (wrapped at rest)
// ---------------------------------------------------------------------------

export async function savePrivateKey(meta, privateKeyArmored, unlockPassphrase) {
  const wrapped = await wrap(privateKeyArmored, unlockPassphrase);
  const record = {
    fingerprint: meta.fingerprint,
    keyID: meta.keyID,
    userIDs: meta.userIDs,
    created: meta.created,
    expiration: meta.expiration || null,
    algorithm: meta.algorithm,
    wrapped,
  };
  await req(STORE_PRIVATE, "readwrite", (os) => os.put(record));
  await savePublicKey(meta); // so we can encrypt to self / share the public half
  return record;
}

export function listPrivateKeys() {
  return req(STORE_PRIVATE, "readonly", getAll).then((rows) => rows.map(({ wrapped, ...rest }) => rest));
}

export async function deletePrivateKey(fingerprint) {
  await forgetSessionKey(fingerprint);
  return req(STORE_PRIVATE, "readwrite", (os) => os.delete(fingerprint));
}

export async function revealPrivateKeyArmored(fingerprint, unlockPassphrase) {
  const row = await req(STORE_PRIVATE, "readonly", (os) => getOne(os, fingerprint));
  if (!row) throw new Error("No such private key.");
  return unwrap(row.wrapped, unlockPassphrase);
}

// ---------------------------------------------------------------------------
// session (unlocked) keys — shared across iframes, session-scoped
// ---------------------------------------------------------------------------

/** Store the DECRYPTED armored secret key for the session. */
export function rememberSessionKey(fingerprint, decryptedArmored) {
  return req(STORE_SESSION, "readwrite", (os) => os.put({ fingerprint, armored: decryptedArmored }));
}

/** [{ fingerprint, armored }] for every currently-unlocked key. */
export function listSessionKeys() {
  return req(STORE_SESSION, "readonly", getAll);
}

export async function isUnlocked(fingerprint) {
  const row = await req(STORE_SESSION, "readonly", (os) => getOne(os, fingerprint));
  return !!row;
}

export function forgetSessionKey(fingerprint) {
  return req(STORE_SESSION, "readwrite", (os) => os.delete(fingerprint));
}

export function wipeSessionKeys() {
  return req(STORE_SESSION, "readwrite", (os) => os.clear());
}
