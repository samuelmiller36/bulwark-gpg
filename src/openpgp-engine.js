// openpgp-engine.js
// Thin, host-agnostic wrapper around openpgp.js. Every function here deals in
// armored strings or plain text so the rest of the plugin never has to touch
// the openpgp object model directly.

import * as openpgp from "openpgp";

const CURVE_FOR_TYPE = {
  ecc: { type: "ecc", curve: "curve25519" },
  rsa4096: { type: "rsa", rsaBits: 4096 },
  rsa2048: { type: "rsa", rsaBits: 2048 },
};

/**
 * Generate a brand new key pair.
 * @returns {{ privateKeyArmored, publicKeyArmored, revocationCertificate, fingerprint, userIDs }}
 */
export async function generateKeyPair({ name, email, passphrase, keyType = "ecc" }) {
  if (!email) throw new Error("An email address is required to generate a key.");
  const algo = CURVE_FOR_TYPE[keyType] || CURVE_FOR_TYPE.ecc;
  const userIDs = [{ name: name || undefined, email }];

  const { privateKey, publicKey, revocationCertificate } = await openpgp.generateKey({
    ...algo,
    userIDs,
    passphrase: passphrase || undefined,
    format: "armored",
  });

  const key = await openpgp.readKey({ armoredKey: publicKey });
  return {
    privateKeyArmored: privateKey,
    publicKeyArmored: publicKey,
    revocationCertificate,
    fingerprint: key.getFingerprint(),
    userIDs: describeUserIDs(key),
  };
}

/** Parse an armored public OR private key block and return its metadata. */
export async function inspectKey(armored) {
  const isPrivate = /BEGIN PGP PRIVATE KEY/.test(armored);
  const key = isPrivate
    ? await openpgp.readPrivateKey({ armoredKey: armored })
    : await openpgp.readKey({ armoredKey: armored });

  let expiration = null;
  try {
    const exp = await key.getExpirationTime();
    expiration = exp === Infinity ? null : exp ? new Date(exp).toISOString() : null;
  } catch (_) {
    /* some keys throw on expiration lookups; treat as non-expiring */
  }

  return {
    isPrivate,
    fingerprint: key.getFingerprint(),
    keyID: key.getKeyID().toHex(),
    userIDs: describeUserIDs(key),
    created: key.getCreationTime().toISOString(),
    expiration,
    // Public half of a private key, so a private import also seeds the keyring.
    publicKeyArmored: isPrivate ? key.toPublic().armor() : armored,
    algorithm: keyAlgorithm(key),
  };
}

/** Parse an already-decrypted armored secret key into an openpgp PrivateKey. */
export function parsePrivateKey(armored) {
  return openpgp.readPrivateKey({ armoredKey: armored });
}

/** Derive the armored public key from an armored (private) key. */
export async function publicFromPrivate(armored) {
  const key = await openpgp.readPrivateKey({ armoredKey: armored });
  return key.toPublic().armor();
}

/** Unlock a passphrase-protected private key. Throws on a wrong passphrase. */
export async function unlockPrivateKey(armored, passphrase) {
  const privateKey = await openpgp.readPrivateKey({ armoredKey: armored });
  if (!privateKey.isDecrypted()) {
    return openpgp.decryptKey({ privateKey, passphrase });
  }
  return privateKey;
}

/**
 * Encrypt (and optionally sign) a UTF-8 string.
 * @param recipientPublicKeysArmored array of armored public keys
 * @param signingKey  an already-unlocked openpgp PrivateKey (or null)
 * @returns armored PGP MESSAGE block
 */
export async function encryptText({ text, recipientPublicKeysArmored, signingKey, algorithm }) {
  const encryptionKeys = await Promise.all(
    recipientPublicKeysArmored.map((a) => openpgp.readKey({ armoredKey: a }))
  );
  const message = await openpgp.createMessage({ text });
  const config = algorithm ? { preferredSymmetricAlgorithm: symmetricEnum(algorithm) } : undefined;

  return openpgp.encrypt({
    message,
    encryptionKeys,
    signingKeys: signingKey || undefined,
    format: "armored",
    config,
  });
}

/** Produce a detached, armored signature over `text`. */
export async function detachedSign({ text, signingKey }) {
  const message = await openpgp.createMessage({ text });
  return openpgp.sign({ message, signingKeys: signingKey, detached: true, format: "armored" });
}

/**
 * Produce an inline cleartext-signed message
 * ("-----BEGIN PGP SIGNED MESSAGE-----"). Used for the legacy inline-PGP
 * compatibility mode where the signature travels inside a text/plain body.
 */
export async function cleartextSign({ text, signingKey }) {
  const message = await openpgp.createCleartextMessage({ text });
  return openpgp.sign({ message, signingKeys: signingKey, format: "armored" });
}

/**
 * Decrypt an armored PGP MESSAGE and verify any embedded signatures.
 * @param decryptionKeys  array of unlocked openpgp PrivateKeys
 * @param verificationKeysArmored  candidate signer public keys
 */
export async function decryptText({ armoredMessage, decryptionKeys, verificationKeysArmored = [] }) {
  const message = await openpgp.readMessage({ armoredMessage });
  const verificationKeys = await Promise.all(
    verificationKeysArmored.map((a) => openpgp.readKey({ armoredKey: a }).catch(() => null))
  );

  const { data, signatures } = await openpgp.decrypt({
    message,
    decryptionKeys,
    verificationKeys: verificationKeys.filter(Boolean),
    expectSigned: false,
  });

  return { text: data, signature: await summariseSignatures(signatures) };
}

/** Verify a cleartext-signed message ("-----BEGIN PGP SIGNED MESSAGE-----"). */
export async function verifyCleartext({ cleartext, verificationKeysArmored = [] }) {
  const signedMessage = await openpgp.readCleartextMessage({ cleartextMessage: cleartext });
  const verificationKeys = await readKeys(verificationKeysArmored);
  const result = await openpgp.verify({ message: signedMessage, verificationKeys });
  return { text: signedMessage.getText(), signature: await summariseSignatures(result.signatures) };
}

/** Verify a detached signature against the exact bytes/text it covers. */
export async function verifyDetached({ text, armoredSignature, verificationKeysArmored = [] }) {
  const message = await openpgp.createMessage({ text });
  const signature = await openpgp.readSignature({ armoredSignature });
  const verificationKeys = await readKeys(verificationKeysArmored);
  const result = await openpgp.verify({ message, signature, verificationKeys });
  return summariseSignatures(result.signatures);
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

async function readKeys(armoredList) {
  const keys = await Promise.all(
    armoredList.map((a) => openpgp.readKey({ armoredKey: a }).catch(() => null))
  );
  return keys.filter(Boolean);
}

function describeUserIDs(key) {
  return key.getUserIDs().map((uid) => {
    const m = /^(.*?)\s*<([^>]+)>\s*$/.exec(uid);
    return m ? { name: m[1].trim(), email: m[2].trim(), raw: uid } : { name: "", email: uid, raw: uid };
  });
}

function keyAlgorithm(key) {
  try {
    const info = key.getAlgorithmInfo();
    return info.bits ? `${info.algorithm}-${info.bits}` : info.curve || info.algorithm;
  } catch (_) {
    return "unknown";
  }
}

function symmetricEnum(name) {
  // openpgp.enums.symmetric: aes128=7, aes192=8, aes256=9
  return { aes128: 7, aes192: 8, aes256: 9 }[name] ?? 9;
}

async function summariseSignatures(signatures) {
  if (!signatures || signatures.length === 0) return { status: "none" };
  const sig = signatures[0];
  try {
    await sig.verified; // throws if the signature does not validate
    return {
      status: "valid",
      keyID: sig.keyID.toHex(),
      created: sig.signature ? (await sig.signature).packets[0]?.created?.toISOString?.() : undefined,
    };
  } catch (err) {
    // A thrown "Could not find signing key" still means the bytes were signed,
    // we just lack the public key to confirm who signed it.
    const unknownKey = /find signing key|No key/i.test(String(err && err.message));
    return { status: unknownKey ? "unknown" : "invalid", keyID: sig.keyID.toHex(), error: String(err && err.message) };
  }
}
