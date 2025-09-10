import { describe, it, expect } from "vitest";
import { validatePKCE, isScopeSubset } from "../src/oauth/internal";
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
