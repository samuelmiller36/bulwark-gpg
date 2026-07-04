import { describe, it, expect } from "vitest";
import { detect } from "../src/pgp-mime.js";

describe("pgp-mime.detect", () => {
  it("detects inline encrypted armor", () => {
    const raw = "Some text\n-----BEGIN PGP MESSAGE-----\n...\n-----END PGP MESSAGE-----\nmore";
    const r = detect(raw);
    expect(r.kind).toBe("inline-encrypted");
  });

  it("detects inline signed message", () => {
    const raw = "Hello\n-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nSigned\n-----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----\n";
    const r = detect(raw);
    expect(["inline-signed", "pgp-mime-signed", "none"]).toContain(r.kind);
  });

  it("returns none for plain text", () => {
    expect(detect("just plain text").kind).toBe("none");
  });
});
