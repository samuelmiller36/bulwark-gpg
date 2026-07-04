// pgp-mime.js
// Build and parse PGP/MIME (RFC 3156) wrappers, and detect PGP content in
// incoming mail (both PGP/MIME and the older "inline" armor style).

const CRLF = "\r\n";

// ---------------------------------------------------------------------------
// detection
// ---------------------------------------------------------------------------

const ARMOR_MESSAGE = /-----BEGIN PGP MESSAGE-----[\s\S]+?-----END PGP MESSAGE-----/;
const ARMOR_SIGNED = /-----BEGIN PGP SIGNED MESSAGE-----[\s\S]+?-----END PGP SIGNATURE-----/;
const ARMOR_PUBKEY = /-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]+?-----END PGP PUBLIC KEY BLOCK-----/;

/**
 * Classify a raw RFC822 message (headers + body).
 * @returns one of: { kind: "pgp-mime-encrypted" | "pgp-mime-signed" |
 *   "inline-encrypted" | "inline-signed" | "none", ... }
 */
export function detect(rawMessage) {
  const { headers, body } = splitHeadersBody(rawMessage);
  const contentType = headers["content-type"] || "";

  if (/multipart\/encrypted/i.test(contentType) && /application\/pgp-encrypted/i.test(rawMessage)) {
    const parts = parseMultipart(rawMessage);
    const ct = parts.find((p) => /application\/octet-stream|application\/pgp-encrypted/i.test(p.contentType) && ARMOR_MESSAGE.test(p.body));
    return { kind: "pgp-mime-encrypted", ciphertext: ct ? extract(ARMOR_MESSAGE, ct.body) : extract(ARMOR_MESSAGE, rawMessage) };
  }

  if (/multipart\/signed/i.test(contentType) && /application\/pgp-signature/i.test(rawMessage)) {
    const parts = parseMultipart(rawMessage);
    const signed = parts[0];
    const sigPart = parts.find((p) => /application\/pgp-signature/i.test(p.contentType));
    return {
      kind: "pgp-mime-signed",
      signedBytes: signed ? signed.raw : "",
      signature: sigPart ? extract(/-----BEGIN PGP SIGNATURE-----[\s\S]+?-----END PGP SIGNATURE-----/, sigPart.body) : "",
      innerContentType: signed ? signed.contentType : "text/plain",
      innerBody: signed ? signed.body : "",
    };
  }

  if (ARMOR_MESSAGE.test(body)) {
    return { kind: "inline-encrypted", ciphertext: extract(ARMOR_MESSAGE, body) };
  }
  if (ARMOR_SIGNED.test(body)) {
    return { kind: "inline-signed", cleartext: extract(ARMOR_SIGNED, body) };
  }
  return { kind: "none" };
}

export function containsPublicKeyBlock(text) {
  return ARMOR_PUBKEY.test(text || "");
}

export function extractPublicKeyBlock(text) {
  return extract(ARMOR_PUBKEY, text || "");
}

// ---------------------------------------------------------------------------
// building (outgoing)
// ---------------------------------------------------------------------------

/**
 * Wrap an armored PGP MESSAGE in a multipart/encrypted (RFC 3156) body.
 * @returns { contentType, contentTransferEncoding, body } — feed to serializeMessage().
 */
export function buildEncrypted({ armoredCiphertext }) {
  const boundary = makeBoundary("enc");
  const contentType = `multipart/encrypted; protocol="application/pgp-encrypted"; boundary="${boundary}"`;
  const body =
    `This is an OpenPGP/MIME encrypted message (RFC 3156).${CRLF}${CRLF}` +
    `--${boundary}${CRLF}` +
    `Content-Type: application/pgp-encrypted${CRLF}` +
    `Content-Description: PGP/MIME version identification${CRLF}${CRLF}` +
    `Version: 1${CRLF}${CRLF}` +
    `--${boundary}${CRLF}` +
    `Content-Type: application/octet-stream; name="encrypted.asc"${CRLF}` +
    `Content-Description: OpenPGP encrypted message${CRLF}` +
    `Content-Disposition: inline; filename="encrypted.asc"${CRLF}${CRLF}` +
    `${normaliseCRLF(armoredCiphertext)}${CRLF}` +
    `--${boundary}--${CRLF}`;
  return { contentType, contentTransferEncoding: "7bit", body };
}

/**
 * Wrap a (already MIME-encoded) inner part plus a detached signature in a
 * multipart/signed body. `signedPart` must be the EXACT bytes that were signed.
 */
export function buildSigned({ signedPart, armoredSignature, micalg = "pgp-sha256" }) {
  const boundary = makeBoundary("sig");
  const contentType = `multipart/signed; micalg="${micalg}"; protocol="application/pgp-signature"; boundary="${boundary}"`;
  const body =
    `This is an OpenPGP/MIME signed message (RFC 3156).${CRLF}${CRLF}` +
    `--${boundary}${CRLF}` +
    `${signedPart}${CRLF}` +
    `--${boundary}${CRLF}` +
    `Content-Type: application/pgp-signature; name="signature.asc"${CRLF}` +
    `Content-Description: OpenPGP digital signature${CRLF}` +
    `Content-Disposition: attachment; filename="signature.asc"${CRLF}${CRLF}` +
    `${normaliseCRLF(armoredSignature)}${CRLF}` +
    `--${boundary}--${CRLF}`;
  return { contentType, body };
}

/**
 * Legacy inline-PGP: put an armored block straight into a text/plain body.
 * Used for both inline-encrypted (armor is a PGP MESSAGE) and inline-signed
 * (armor is a PGP SIGNED MESSAGE) compatibility sends. No multipart wrapper.
 */
export function buildInline({ armor }) {
  return { contentType: 'text/plain; charset="utf-8"', contentTransferEncoding: "7bit", body: `${normaliseCRLF(armor)}${CRLF}` };
}

/**
 * Serialise an envelope + content part into a full RFC822 message string,
 * ready to be encoded to bytes for host.jmap.sendRaw().
 */
export function serializeMessage({ from, to, cc, subject, inReplyTo, references, contentType, contentTransferEncoding, body }) {
  const lines = [];
  const add = (name, value) => {
    if (value) lines.push(`${name}: ${value}`);
  };
  add("Date", new Date().toUTCString());
  add("Message-ID", `<${Math.random().toString(36).slice(2)}.${Date.now().toString(36)}@openpgp.local>`);
  add("From", from);
  add("To", to);
  add("Cc", cc);
  add("Subject", subject);
  add("In-Reply-To", inReplyTo);
  add("References", references);
  lines.push("MIME-Version: 1.0");
  add("Content-Type", contentType);
  add("Content-Transfer-Encoding", contentTransferEncoding);
  return `${lines.join(CRLF)}${CRLF}${CRLF}${body}`;
}

/**
 * Parse a decrypted/verified MIME entity (string) into a renderable body.
 * Handles single text/plain & text/html leaves, multipart/{alternative,mixed,
 * related,signed} trees, and base64 / quoted-printable transfer encodings.
 * @returns { html, text, attachments: [{filename, contentType}] }
 */
export function renderInnerMime(raw) {
  const out = { html: "", text: "", attachments: [] };
  walkEntity(String(raw), out);
  return out;
}

function walkEntity(entity, out) {
  const { headers, body } = splitHeadersBody(entity);
  const ct = (headers["content-type"] || "text/plain").toLowerCase();
  const cte = (headers["content-transfer-encoding"] || "7bit").toLowerCase().trim();
  const disposition = (headers["content-disposition"] || "").toLowerCase();

  if (ct.startsWith("multipart/")) {
    const parts = parseMultipart(entity);
    if (ct.startsWith("multipart/alternative")) {
      // Prefer the richest representation the host can show (html > plain).
      const htmlPart = parts.find((p) => /text\/html/i.test(p.contentType));
      const textPart = parts.find((p) => /text\/plain/i.test(p.contentType));
      if (htmlPart) walkEntity(htmlPart.raw, out);
      else if (textPart) walkEntity(textPart.raw, out);
      else parts.forEach((p) => walkEntity(p.raw, out));
    } else {
      // mixed / related / signed: walk every part in order.
      parts.forEach((p) => walkEntity(p.raw, out));
    }
    return;
  }

  const isAttachment = /attachment/.test(disposition) || /name=|filename=/.test(disposition + ct);
  if (isAttachment && !ct.startsWith("text/")) {
    const m = /filename="?([^";]+)"?|name="?([^";]+)"?/i.exec(disposition + "; " + ct);
    out.attachments.push({ filename: (m && (m[1] || m[2])) || "attachment", contentType: ct.split(";")[0].trim() });
    return;
  }

  const charset = (/charset="?([^";]+)"?/i.exec(ct) || [])[1] || "utf-8";
  const decoded = decodeContent(body, cte, charset);
  if (ct.startsWith("text/html")) {
    out.html = out.html || decoded;
    if (!out.text) out.text = stripHtml(decoded);
  } else if (ct.startsWith("text/")) {
    out.text = out.text || decoded;
  }
}

function decodeContent(body, cte, charset) {
  let bytes;
  if (cte === "base64") {
    try {
      bytes = Uint8Array.from(atob(body.replace(/\s+/g, "")), (c) => c.charCodeAt(0));
    } catch {
      return body;
    }
  } else if (cte === "quoted-printable") {
    const t = body.replace(/=\r?\n/g, "").replace(/=([0-9A-Fa-f]{2})/g, (_, hh) => String.fromCharCode(parseInt(hh, 16)));
    bytes = Uint8Array.from(t, (c) => c.charCodeAt(0));
  } else {
    // 7bit / 8bit / binary — already text, but normalise via utf-8 for safety.
    try {
      return new TextDecoder(safeCharset(charset)).decode(new TextEncoder().encode(body));
    } catch {
      return body;
    }
  }
  try {
    return new TextDecoder(safeCharset(charset), { fatal: false }).decode(bytes);
  } catch {
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  }
}

function safeCharset(cs) {
  const c = String(cs || "utf-8").toLowerCase().replace(/^"|"$/g, "");
  if (/^(us-ascii|ascii)$/.test(c)) return "utf-8";
  return c;
}

/**
 * Privacy pass over rendered HTML. Runs after MIME extraction, before the body
 * is handed to the host (which then applies its own sanitizer).
 *  - blockRemoteContent: neutralise anything that would fetch from the network
 *    (remote img/media/iframe src, srcset, CSS url(), <link> stylesheets). Inline
 *    data:/cid: resources are preserved.
 *  - disableExternalLinks: render http(s) links as inert text; otherwise harden
 *    them with rel="noopener noreferrer" target="_blank".
 * @returns { html, blockedRemote }
 */
export function sanitizeHtml(html, { blockRemoteContent = true, disableExternalLinks = false } = {}) {
  let out = String(html);
  let blockedRemote = 0;
  const isRemote = (u) => /^\s*(?:https?:)?\/\//i.test(u || "") || /^\s*https?:/i.test(u || "");

  if (blockRemoteContent) {
    out = out.replace(/\b(src|background|poster)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi, (m, attr, dq, sq, uq) => {
      const url = dq ?? sq ?? uq ?? "";
      if (isRemote(url)) {
        blockedRemote++;
        return `data-blocked-${attr.toLowerCase()}="${escapeAttr(url)}"`;
      }
      return m;
    });
    out = out.replace(/\bsrcset\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, () => {
      blockedRemote++;
      return "data-blocked-srcset";
    });
    out = out.replace(/<link\b[^>]*>/gi, (m) => {
      const hm = /href\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(m);
      const url = hm ? hm[1] ?? hm[2] : "";
      if (isRemote(url)) {
        blockedRemote++;
        return "";
      }
      return m;
    });
    out = out.replace(/url\(\s*(['"]?)([^)'"]*)\1\s*\)/gi, (m, _q, url) => {
      if (isRemote(url)) {
        blockedRemote++;
        return "url()";
      }
      return m;
    });
  }

  out = out.replace(/<a\b([^>]*)>/gi, (m, attrs) => {
    const hm = /href\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(attrs);
    const url = hm ? hm[1] ?? hm[2] : "";
    if (!isRemote(url)) return m;
    if (disableExternalLinks) {
      const cleaned = attrs
        .replace(/\shref\s*=\s*(?:"[^"]*"|'[^']*')/i, "")
        .replace(/\starget\s*=\s*(?:"[^"]*"|'[^']*')/i, "");
      return `<a${cleaned} data-disabled-link="${escapeAttr(url)}" title="External link disabled: ${escapeAttr(url)}" style="cursor:not-allowed">`;
    }
    let a = attrs;
    if (!/\brel\s*=/i.test(a)) a += ' rel="noopener noreferrer"';
    if (!/\btarget\s*=/i.test(a)) a += ' target="_blank"';
    return `<a${a}>`;
  });

  return { html: out, blockedRemote };
}

function escapeAttr(s) {
  return String(s).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function stripHtml(html) {
  return String(html)
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .replace(/[ \t]{2,}/g, " ")
    .trim();
}

/**
 * Render the plaintext body into a canonical MIME leaf part. The returned
 * string is what gets signed (so the receiver verifies the same bytes).
 */
export function buildTextPart(text) {
  return (
    `Content-Type: text/plain; charset="utf-8"${CRLF}` +
    `Content-Transfer-Encoding: quoted-printable${CRLF}${CRLF}` +
    quotedPrintable(normaliseCRLF(text))
  );
}

// ---------------------------------------------------------------------------
// MIME plumbing
// ---------------------------------------------------------------------------

export function splitHeadersBody(raw) {
  const idx = raw.search(/\r?\n\r?\n/);
  if (idx === -1) return { headers: {}, body: raw, headerText: "" };
  const headerText = raw.slice(0, idx);
  const body = raw.slice(idx).replace(/^\r?\n\r?\n/, "");
  return { headers: parseHeaders(headerText), body, headerText };
}

function parseHeaders(headerText) {
  const headers = {};
  // unfold continuation lines (leading whitespace)
  const unfolded = headerText.replace(/\r?\n[ \t]+/g, " ");
  for (const line of unfolded.split(/\r?\n/)) {
    const m = /^([^:]+):\s?([\s\S]*)$/.exec(line);
    if (m) headers[m[1].trim().toLowerCase()] = m[2];
  }
  return headers;
}

function parseMultipart(raw) {
  const { headers, body } = splitHeadersBody(raw);
  const ct = headers["content-type"] || "";
  const bm = /boundary="?([^";]+)"?/i.exec(ct);
  if (!bm) return [];
  const boundary = bm[1];

  // Locate every boundary delimiter by position so we can slice out the EXACT
  // bytes of each part — required for RFC 3156 signature verification, where
  // the signed part must be reproduced byte-for-byte. The CRLF immediately
  // preceding a boundary delimiter belongs to the delimiter, not the part.
  const delim = new RegExp(`(?:\\r?\\n)?--${escapeRegExp(boundary)}(--)?[ \\t]*\\r?\\n`, "g");
  const marks = [];
  let mm;
  while ((mm = delim.exec(body))) {
    marks.push({ index: mm.index, end: delim.lastIndex, closing: !!mm[1] });
  }
  if (marks.length === 0) return [];

  const parts = [];
  for (let i = 0; i < marks.length - 1; i++) {
    if (marks[i].closing) break;
    const segment = body.slice(marks[i].end, marks[i + 1].index); // preamble before marks[0] is skipped
    const { headers: h, body: b, headerText } = splitHeadersBody(segment);
    parts.push({
      contentType: h["content-type"] || "text/plain",
      headers: h,
      body: b,
      raw: segment, // exact original bytes between the two delimiters
      headerText,
    });
  }
  return parts;
}

function extract(re, text) {
  const m = re.exec(text || "");
  return m ? m[0] : "";
}

function makeBoundary(prefix) {
  return `=_${prefix}_${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`;
}

function normaliseCRLF(s) {
  return String(s).replace(/\r\n/g, "\n").replace(/\n/g, CRLF);
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function quotedPrintable(input) {
  return input
    .split(CRLF)
    .map((line) =>
      line
        .replace(/[=\x00-\x08\x0b\x0c\x0e-\x1f\x7f-￿]/g, (c) => {
          const bytes = new TextEncoder().encode(c);
          return [...bytes].map((b) => "=" + b.toString(16).toUpperCase().padStart(2, "0")).join("");
        })
        // trailing whitespace must be encoded
        .replace(/([ \t])$/g, (m) => "=" + m.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0"))
    )
    .join(CRLF);
}
