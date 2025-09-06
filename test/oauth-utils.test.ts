import { describe, it, expect } from "vitest";
import {
  validatePKCE,
  normalizeScope,
  isScopeSubset,
} from "../src/oauth/internal";
import { hash } from "unsecure";

describe("oauth/utils", () => {
  describe("validatePKCE", () => {
    it("validates plain method", async () => {
      const verifier = "test-verifier-123";
      const challenge = verifier; // plain
      await expect(validatePKCE(verifier, challenge, "plain")).resolves.toBe(
        true,
      );
      await expect(validatePKCE("other", challenge, "plain")).resolves.toBe(
        false,
      );
    });

    it("validates S256 method", async () => {
      const verifier = "another-verifier-456";
      const challenge = await hash(verifier, {
        algorithm: "SHA-256",
        returnAs: "b64url",
      });
      await expect(validatePKCE(verifier, challenge, "S256")).resolves.toBe(
        true,
      );
      await expect(validatePKCE("wrong", challenge, "S256")).resolves.toBe(
        false,
      );
      // wrong method
      await expect(validatePKCE(verifier, challenge, "plain")).resolves.toBe(
        false,
      );
    });
  });

  describe("normalizeScope", () => {
    it("dedupes regardless of available list", () => {
      const out1 = normalizeScope("read write read", undefined, [
        "read",
        "write",
      ]);
      const out2 = normalizeScope("read write read", undefined, undefined);
      expect(out1).toBe("read write");
      expect(out2).toBe("read write");
    });

    it("uses fallback when requested missing", () => {
      const out = normalizeScope(undefined, "openid profile", undefined);
      expect(out).toBe("openid profile");
    });

    it("throws when both requested and fallback are missing", () => {
      expect(() =>
        normalizeScope(undefined, undefined, undefined),
      ).toThrowError(/Missing scope/);
    });

    it("validates against available scopes", () => {
      const available = ["read", "write", "openid", "profile"];
      const ok = normalizeScope("read write", undefined, available);
      expect(ok).toBe("read write");
      expect(() =>
        normalizeScope("read admin", undefined, available),
      ).toThrowError(/Invalid scope: admin/);
    });
  });

  describe("isScopeSubset", () => {
    it("accepts subset and equal", () => {
      expect(isScopeSubset("read", "read write")).toBe(true);
      expect(isScopeSubset("read write", "read write")).toBe(true);
    });

    it("rejects superset and disjoint", () => {
      expect(isScopeSubset("read write admin", "read write")).toBe(false);
      expect(isScopeSubset("admin", "read write")).toBe(false);
    });
  });
});
