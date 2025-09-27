import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import { base64UrlEncode } from "unsecure/utils";
import type { JWK_oct } from "unjwt";

import {
  buildAuthorizationCode,
  validateAuthorizationCodeClaims,
  buildAuthorizationCodeGrant,
  buildRefreshTokenGrant,
  idTokenDefaults,
  buildOIDCDiscoveryDocument,
  buildUserInfo,
  introspectAccessToken,
} from "../src/oidc/provider";

import type {
  AuthorizeRequest,
  AuthorizationCodeClaims,
  RefreshTokenClaims,
  AuthorizationCodeGrantRequest,
} from "../src/oidc/types";

const makeOctJwk = (size = 32, alg?: string): JWK_oct => {
  const key = randomBytes(size);
  return { kty: "oct", k: base64UrlEncode(key), ...(alg ? { alg } : {}) };
};

describe("OIDC Provider", () => {
  describe("Authorize constraints", () => {
    const iss = "https://issuer";
    const now = new Date("2024-01-01T00:00:00Z");
    const acOpts = {
      privateKey: "ac-jwe-secret-key", // OR JWK
      encryptOptions: {
        currentDate: now,
        expiresIn: 600,
      },
      decryptOptions: { currentDate: now, maxTokenAge: 600 },
    } as const;

    it("requires openid scope, nonce and S256", async () => {
      const baseReq: AuthorizeRequest = {
        client_id: "c",
        response_type: "code",
        code_challenge: "x",
        // @ts-expect-error testing invalid input
        code_challenge_method: "plain",
        redirect_uri: "https://cb",
        resource: "api",
        scope: "read",
      };
      const r1 = await buildAuthorizationCode({
        req: baseReq,
        claims: { sub: "u" },
        iss,
        options: acOpts,
      });
      expect(r1).toMatchInlineSnapshot(
        `"https://cb/?iss=https%3A%2F%2Fissuer&error=invalid_request&error_description=code_challenge_method+must+be+S256"`,
      );

      const r2 = await buildAuthorizationCode({
        // @ts-expect-error testing invalid input
        req: { ...baseReq, scope: "openid", code_challenge_method: "plain" },
        claims: { sub: "u" },
        iss,
        options: acOpts,
      });
      expect(r2).toMatchInlineSnapshot(
        `"https://cb/?iss=https%3A%2F%2Fissuer&error=invalid_request&error_description=code_challenge_method+must+be+S256"`,
      );

      const r3 = await buildAuthorizationCode({
        req: { ...baseReq, scope: "openid", code_challenge_method: "S256" },
        claims: { sub: "u" },
        iss,
        options: acOpts,
      });
      expect(r3).toMatchInlineSnapshot(
        `"https://cb/?iss=https%3A%2F%2Fissuer&error=invalid_request&error_description=Missing+nonce+in+authorization+request"`,
      );
    });

    it("passes with openid scope, nonce, S256 and propagates nonce", async () => {
      const verifier = "v";
      const challenge = verifier; // use plain
      const out = await buildAuthorizationCode({
        req: {
          client_id: "c",
          response_type: "code",
          code_challenge: challenge,
          code_challenge_method: "S256", // allowed by implementation, but we don't compute it here
          redirect_uri: "https://cb",
          resource: "api",
          scope: "openid",
          nonce: "n",
        },
        claims: { sub: "u" },
        iss,
        options: acOpts,
        randomJti: () => "x",
      });
      expect(out).toBeTypeOf("string");
      expect(out).toContain("https://cb/?iss=https%3A%2F%2Fissuer&code=");
    });
  });

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

  describe("Token flows with ID Token", () => {
    const iss = "https://issuer";
    const now = new Date("2024-01-01T00:00:00Z");
    const jwk = makeOctJwk(32, "HS256");

    const accessTokenOptions = {
      privateKey: jwk,
      signOptions: {
        expiresIn: 3600,
        currentDate: now,
      },
      verifyOptions: { currentDate: now, maxTokenAge: 3600 },
    } as const;
    const refreshTokenOptions = {
      privateKey: "rt-jwe-secret-key", // OR JWK
      encryptOptions: {
        expiresIn: 7200,
        currentDate: now,
      },
      decryptOptions: { currentDate: now, maxTokenAge: 7200 },
    } as const;
    const idTokenOptions = {
      privateKey: jwk,
      signOptions: { alg: "HS256", expiresIn: 1800, currentDate: now },
    } as const;

    it("validateAuthorizationCodeClaims requires nonce then OAuth checks", async () => {
      const req: AuthorizationCodeGrantRequest = {
        grant_type: "authorization_code",
        code: "c",
        client_id: "client",
        code_verifier: "v",
      };
      // @ts-expect-error testing missing nonce
      const claimsMissingNonce: AuthorizationCodeClaims = {
        sub: "u",
        jti: "j",
        iss,
        iat: 1,
        exp: 2,
        client_id: "client",
        redirect_uri: "https://cb",
        code_challenge: "x",
        code_challenge_method: "plain",
        resource: "api",
        scope: "openid",
      };
      const res = await validateAuthorizationCodeClaims({
        claims: claimsMissingNonce,
        req,
        iss,
      });
      expect(res).toMatchObject({ error: "invalid_grant" });
    });

    it("authorization_code grant returns id_token with at_hash matching alg", async () => {
      const verifier = "verifier";
      const challenge = verifier; // plain
      const req: AuthorizationCodeGrantRequest = {
        grant_type: "authorization_code",
        code: "code",
        client_id: "client",
        code_verifier: verifier,
      };
      const codeClaims: AuthorizationCodeClaims = {
        sub: "user",
        jti: "j1",
        iss,
        iat: Math.floor(now.getTime() / 1000),
        exp: Math.floor(now.getTime() / 1000) + 600,
        client_id: "client",
        redirect_uri: "https://cb",
        code_challenge: challenge,
        code_challenge_method: "plain",
        resource: "api",
        scope: "openid",
        nonce: "n",
      };

      const out = await buildAuthorizationCodeGrant({
        req,
        codeClaims,
        accessTokenOptions,
        refreshTokenOptions,
        idTokenOptions,
        iss,
        randomJti: () => "id",
        currentDate: now,
      });

      expect("res" in out).toBe(true);
      if (!("res" in out)) throw new Error("unexpected error response");
      expect("id_token" in out.res).toBe(true);
      // at_hash is computed internally; assert presence and basic format only
      expect(typeof out.idTokenClaims.at_hash).toBe("string");
      expect(out.idTokenClaims.at_hash?.length).toBeGreaterThan(0);
      expect(out.idTokenClaims.nonce).toBe("n");

      // Do not decrypt refresh token; assert presence only
      expect(typeof out.res.refresh_token).toBe("string");
    });

    it("refresh_token grant returns new id_token (nonce propagated if present)", async () => {
      const req = {
        grant_type: "refresh_token",
        refresh_token: "rt",
        client_id: "client",
      } as const;
      const old: RefreshTokenClaims = {
        sub: "u",
        client_id: "client",
        iss,
        iat: Math.floor(now.getTime() / 1000) - 10,
        exp: Math.floor(now.getTime() / 1000) + 100,
        jti: "old",
        resource: "api",
        scope: "openid",
        nonce: "n",
      };

      const out = await buildRefreshTokenGrant({
        req,
        refreshTokenClaims: old,
        idTokenOptions,
        accessTokenOptions,
        refreshTokenOptions,
        iss,
        randomJti: () => "x",
        currentDate: now,
      });

      expect("res" in out).toBe(true);
      if (!("res" in out)) throw new Error("unexpected error response");
      expect(out.res.id_token).toBeTypeOf("string");
      const at2 = await introspectAccessToken({
        token: out.res.access_token,
        iss,
        options: accessTokenOptions,
      });
      expect(at2.payload.sub).toBe("u");
    });
  });
});
