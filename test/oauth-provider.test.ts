import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import { base64UrlEncode } from "unsecure/utils";
import type { JWK_oct } from "unjwt";

import {
  OAuthError,
  authorizationCodeDefaults,
  refreshTokenDefaults,
  accessTokenDefaults,
  DEFAULTS_OPTIONS,
  buildOAuthDiscoveryDocument,
  validatePKCE,
  isScopeSubset,
} from "../src/oauth/provider";

// Helpers

const makeOctJwk = (size = 32, alg?: string): JWK_oct => {
  const key = randomBytes(size);
  // intentionally mocking keys instead of using unjwt's generateKey
  return { kty: "oct", k: base64UrlEncode(key), ...(alg ? { alg } : {}) };
};

describe("OAuth Provider", () => {
  describe("Error", () => {
    it("constructs and serializes OAuthError with details", () => {
      const err = new OAuthError({
        error: "invalid_request",
        error_description: "Bad",
        error_uri: "https://example.com/e",
        state: "s",
        iss: "iss",
        realm: "r",
      });
      expect(err.name).toBe("OAuthError");
      expect(err.error).toBe("invalid_request");
      expect(err.message).toContain("OAuthError invalid_request Bad");
      const json = err.toJSON();
      expect(json).toEqual(
        expect.objectContaining({
          error: "invalid_request",
          error_description: "Bad",
          error_uri: "https://example.com/e",
          state: "s",
          iss: "iss",
          realm: "r",
        }),
      );
      expect(OAuthError.isError(err)).toBe(true);
    });

    it("uses cause and infers error fields", () => {
      const cause = new Error("Boom");
      // Attach an OAuth-shaped cause for inference
      cause.cause = {
        error: "invalid_scope",
        error_description: "no",
      };
      const err = new OAuthError(cause);
      expect(err.error).toBe("invalid_scope");
      expect(err.error_description).toBe("no");
    });
  });

  describe("Defaults", () => {
    it("authorizationCodeDefaults fills expiresIn", () => {
      const key = makeOctJwk();
      const out = authorizationCodeDefaults({ privateKey: key });
      expect(out.encryptOptions.expiresIn).toBe(
        DEFAULTS_OPTIONS.authorizationCode.expiresIn,
      );
      expect(out.decryptOptions?.maxTokenAge).toBe(
        DEFAULTS_OPTIONS.authorizationCode.expiresIn,
      );
    });

    it("refreshTokenDefaults fills expiresIn", () => {
      const key = makeOctJwk();
      const out = refreshTokenDefaults({ privateKey: key });
      expect(out.encryptOptions.expiresIn).toBe(
        DEFAULTS_OPTIONS.refreshToken.expiresIn,
      );
      expect(out.decryptOptions?.maxTokenAge).toBe(
        DEFAULTS_OPTIONS.refreshToken.expiresIn,
      );
    });

    it("accessTokenDefaults fills expiresIn", () => {
      const key = makeOctJwk(32, "HS256");
      const out = accessTokenDefaults({ privateKey: key });
      expect(out.signOptions.expiresIn).toBe(
        DEFAULTS_OPTIONS.accessToken.expiresIn,
      );
      expect(out.verifyOptions?.maxTokenAge).toBe(
        DEFAULTS_OPTIONS.accessToken.expiresIn,
      );
    });
  });

  describe("Discovery", () => {
    it("builds discovery document with prefix normalization", () => {
      const doc = buildOAuthDiscoveryDocument({
        issuer: "https://auth.example.com/",
        prefix: "/oauth/v1/",
      });
      expect(doc.issuer).toBe("https://auth.example.com/");
      expect(doc.authorization_endpoint).toBe(
        "https://auth.example.com/oauth/v1/authorize",
      );
      expect(doc.token_endpoint).toBe(
        "https://auth.example.com/oauth/v1/token",
      );
      expect(doc.introspection_endpoint).toBe(
        "https://auth.example.com/oauth/v1/introspect",
      );
      expect(doc.jwks_uri).toBe(
        "https://auth.example.com/oauth/v1/.well-known/jwks.json",
      );
    });
  });

  describe("Utils", () => {
    it("validatePKCE works for plain and mismatch cases", async () => {
      const verifier = "some-very-random-verifier";
      expect(await validatePKCE(verifier, verifier, "plain")).toBe(true);
      expect(await validatePKCE("nope", verifier, "plain")).toBe(false);
    });

    // TODO: add S256 test with real hashing

    it("isScopeSubset validates subset correctly", () => {
      expect(isScopeSubset("a b", "a b c")).toBe(true);
      expect(isScopeSubset("a b c", "a b")).toBe(false);
      // TODO: Implementation treats empty requested string as not a subset
      expect(isScopeSubset("", "a b")).toBe(false);
    });
  });
});
