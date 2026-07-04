import { describe, it, expect } from "vitest";
import { normalizeHex, classifyQuery } from "../src/keyserver.js";

describe("normalizeHex", () => {
  it("strips 0x and whitespace and uppercases", () => {
    expect(normalizeHex("0x a b c d")).toBe("ABCD");
  });

  it("returns empty for non-hex", () => {
    expect(normalizeHex("zzzz")).toBe("");
  });
});

describe("classifyQuery", () => {
  it("classifies emails", () => {
    expect(classifyQuery("alice@example.com")).toEqual({ kind: "email", value: "alice@example.com" });
  });

  it("classifies 40-char fingerprint", () => {
    const fp = "a".repeat(40);
    expect(classifyQuery(fp).kind).toBe("fingerprint");
  });

  it("classifies 16-char keyid", () => {
    const id = "a".repeat(16);
    expect(classifyQuery(id).kind).toBe("keyid");
  });

  it("classifies invalid inputs", () => {
    expect(classifyQuery("not a thing").kind).toBe("invalid");
  });
});
