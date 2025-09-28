import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import { base64UrlEncode } from "unsecure/utils";
import type { JWK_oct } from "unjwt";

import {
  idTokenDefaults,
  buildOIDCDiscoveryDocument,
  buildUserInfo,
} from "../src/oidc/provider";

const makeOctJwk = (size = 32, alg?: string): JWK_oct => {
  const key = randomBytes(size);
  return { kty: "oct", k: base64UrlEncode(key), ...(alg ? { alg } : {}) };
};

describe("OIDC Provider", () => {
  describe("Discovery + defaults", () => {
    it("builds OIDC discovery and idTokenDefaults", () => {
      const doc = buildOIDCDiscoveryDocument({
        issuer: "https://auth/",
        prefix: "/oidc",
      });
      expect(doc.userinfo_endpoint).toBe("https://auth/oidc/userinfo");
      expect(doc.scopes_supported).toContain("openid");

      const jwk = makeOctJwk(32, "HS256");
      const idOpts = idTokenDefaults({ privateKey: jwk });
      expect(idOpts.signOptions.expiresIn).toBeGreaterThan(0);
    });
  });

  describe("UserInfo sanitizer", () => {
    it("keeps allowed types and drops unsafe", () => {
      const out = buildUserInfo({
        sub: "user",
        name: "Name",
        email: "u@e",
        email_verified: true,
        address: { street: "x" },
        updated_at: 123,
        __proto__: "oops",
        extra: 42,
      });
      expect(out.sub).toBe("user");
      expect(out.email_verified).toBe(true);
      // __proto__ should not poison prototype; library returns own enumerable field as plain object at most
      expect(Object.prototype.hasOwnProperty.call(out, "__proto__")).toBe(
        false,
      );
      expect(out.extra).toBe(42);
    });

    it("throws on invalid sub type", () => {
      // @ts-expect-error testing invalid input
      expect(() => buildUserInfo({ sub: 1 })).toThrow(/userinfo.sub/);
    });
  });
});
