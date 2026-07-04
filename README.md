# OpenPGP for Bulwark Mail

End-to-end **OpenPGP** (GnuPG-compatible) encryption, signing and key management
for Bulwark Mail webmail. All cryptography runs locally in your browser using a
bundled [openpgp.js](https://openpgpjs.org/) engine — secret keys never leave the
device.

This plugin is the OpenPGP counterpart to the bundled `smime` plugin and follows
the same privileged (same-origin) plugin tier.

## Features

- **Key management** — generate ECC (curve25519) or RSA key pairs, import/export
  ASCII-armored **public and private** keys, and store recipient keys for
  encryption. Keys live in a per-account IndexedDB keyring.
- **Key exchange** — copy your armored public key to share it, paste in someone
  else's, and auto-import a signer's public key from incoming signed mail.
- **Encrypt** outgoing mail to one or more recipients (PGP/MIME, RFC 3156). The
  message is always encrypted to yourself too, so it stays readable in *Sent*.
- **Sign** outgoing mail with a detached PGP/MIME signature, or sign-and-encrypt
  in one step.
- **Inline-PGP compatibility mode** — optionally send body-embedded armor
  (inline encrypted, or `BEGIN PGP SIGNED MESSAGE` cleartext signatures) for
  older clients that don't speak PGP/MIME. Toggle via *Outgoing message format*.
- **Attach my key** — a one-click composer button that copies your armored
  public key to the clipboard so you can paste it into a message and let
  recipients reply encrypted.
- **Decrypt & verify** incoming PGP/MIME *and* legacy inline-PGP messages
  automatically, with a status banner showing signature validity and the signer.
- **Keyserver lookup & fingerprint confirmation** — find a recipient's public
  key on [keys.openpgp.org](https://keys.openpgp.org) by fingerprint or (owner-
  verified) email, machine-verify that the returned key really carries the
  fingerprint you asked for, visually confirm it (grouped hex + a colour
  "barcode"), then import it. See below.
- **Publish your key** — one-click **Publish** on a personal key uploads its
  *public* half to keys.openpgp.org and triggers the address-verification email
  that makes it discoverable by email. Your secret key is never uploaded.

## Security model

| Concern | Approach |
| --- | --- |
| Secret keys at rest | Armored private key wrapped with **AES-256-GCM** under a **PBKDF2(SHA-256, 600 000)** key derived from your at-rest passphrase, stored in IndexedDB. |
| Secret keys in use | Unlocked into an in-memory `openpgp` key object for the session only. |
| Logout / account switch | Unlocked keys are wiped from memory (configurable via *Lock keys on logout*). |
| Rendering | Decrypted HTML is returned to the host, which re-sanitises it before display. |

> **Note:** unlocking a key requires the at-rest passphrase. When you generate a
> key, its PGP passphrase is reused as the at-rest passphrase.

## Architecture

The plugin follows Bulwark's sandboxed contract: it exports `slots`, `hooks`
and `activate`, and obtains the host API via `require('@plugin-host')`. The
background (hook) iframe and the slot (UI) iframes are **separate documents**,
so all shared state lives in `host.storage` / IndexedDB — never in module memory.

```
src/
├── index.js            # hooks + slots + activate; all UI components
├── openpgp-engine.js   # thin wrapper over openpgp.js (gen/encrypt/decrypt/sign/verify)
├── key-storage.js      # IndexedDB keyring + at-rest AES-GCM wrap + shared session store
└── pgp-mime.js         # RFC 3156 PGP/MIME build + serialize + parse + PGP detection
```

### Cross-iframe state (host.storage / IndexedDB)

| State | Where | Written by | Read by |
| --- | --- | --- | --- |
| Compose intent (sign/encrypt) | `host.storage["composeIntent.v1"]` | composer-toolbar slot | `onComposeSend` |
| Per-message verify status | `host.storage["verify:<id>"]` | `onRenderEmailBody` | email-banner slot |
| Unlocked secret keys | IndexedDB `session-keys` store | settings slot (unlock) | `onComposeSend` / `onRenderEmailBody` |

Unlocked keys are stored as the *decrypted armored* secret key in a session
IndexedDB store so every same-origin iframe can use them; the store is wiped on
app boot and on logout/account-switch.

### Hooks

| Hook | Purpose |
| --- | --- |
| `onComposeSend(req)` | Build signed/encrypted RFC822 bytes and submit via `host.jmap.sendRaw(bytes, identityId, opts)`. Returns `false` to take over the send. |
| `onRenderEmailBody(body, ctx)` | `host.jmap.fetchBlob(ctx.blobId)`, decrypt/verify, return `{ ...body, html, text, verification }`. |
| `onAfterLogout` / `onAccountSwitch` | Wipe the unlocked-key session store. |

### Slots

`settings-section` (key manager) · `composer-toolbar` (Sign/Encrypt + Attach my
key) · `email-banner` (signature & encryption status).

## Build & install

```bash
npm install
npm run build      # bundles src/index.js -> dist/index.js (openpgp.js inlined)
npm run package    # build + zip manifest.json, index.js and media/ into openpgp.zip
```

Then upload `openpgp.zip` via **Admin → Plugins** in Bulwark Mail.

React / ReactDOM are provided by the host and are marked external in the build,
so they are not duplicated in the bundle.

### Auditability / bundle notes (for reviewers)

- `dist/index.js` is an **unminified** esbuild bundle of the source in `src/`
  plus **openpgp.js 6.3.1**. The readable source and build config are shipped in
  the package under `source/` so the bundle is reproducible (`npm ci && npm run
  build`).
- The build targets openpgp.js's **lightweight** entry
  (`dist/lightweight/openpgp.mjs`), so the bundle contains **no embedded
  WebAssembly** and **no long base64 blobs**. openpgp.js's optional Argon2 S2K
  module (`argon2id.mjs`, the only WASM carrier) is marked external and is **not
  shipped**: it is only ever loaded for password-based Argon2 S2K messages, which
  this plugin's public-key mail flows never produce. The single remaining
  `WebAssembly` token in the bundle is a string literal in openpgp.js's
  Safari out-of-memory error check, not a WebAssembly instantiation.

## Usage

1. Open **Settings → OpenPGP keys** and either **Generate a new key pair** or
   **Import** an existing one. Set an at-rest passphrase.
2. Click **Unlock** on your key (once per session) to enable signing/decryption.
3. **Copy public key** and share it; **Import** your contacts' public keys.
4. In the composer, toggle **Sign** and/or **Encrypt** before sending. Encryption
   requires a stored public key for every recipient.
5. Incoming PGP mail is decrypted/verified automatically; the banner shows status.

### Looking up & confirming a key from a keyserver

Under **Recipient keys**, click **🔍 Find a key on keys.openpgp.org** and enter
either a full **fingerprint** (40 or 64 hex chars, spaces and a `0x` prefix are
ignored) or an **email address**. The plugin fetches the key over the
[VKS API](https://keys.openpgp.org/about/api) and shows a confirmation card:

- **By fingerprint** — the plugin re-derives the fingerprint from the returned
  key and only accepts it if it *exactly* matches your query. A keyserver that
  substitutes a different key is rejected. You see a green **✓ Verified** banner.
- **By email** — keys.openpgp.org only serves addresses the owner has verified,
  but you still can't know the key is theirs from the server alone, so the card
  shows an amber prompt to **confirm the fingerprint out-of-band** (in person,
  by phone, over Signal…) before importing.

Every result renders the fingerprint as **grouped hex** plus a deterministic
colour **barcode** so you can eyeball-compare it against the copy the owner gave
you. Nothing is ever *uploaded* — the plugin only fetches keys you search for.
The keyserver and the on/off switch are configurable in the plugin settings
(*Look up keys on a keyserver*, *Keyserver URL*).

> **Host networking:** keyserver lookup makes an outbound `fetch()`. The plugin
> declares the `http:fetch` permission and lists `https://keys.openpgp.org` in
> its manifest `httpOrigins` allowlist. To point *Keyserver URL* at a different
> host, add that origin to `httpOrigins` too. If the request is still blocked,
> the tool degrades gracefully with a clear message — import the key by paste
> instead.

## License

See repository root `LICENSE`.
