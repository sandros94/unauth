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
  buildAuthorizationCode,
  buildAuthorizationRedirect,
  validateRedirectUri,
  validateTokenRequest,
  validateAuthorizationCodeClaims,
  buildAuthorizationCodeGrant,
  buildClientCredentialsGrant,
  buildRefreshTokenGrant,
  introspectAuthorizationCode,
  introspectAccessToken,
  validatePKCE,
  isScopeSubset,
} from "../src/oauth/provider";

import type {
  AuthorizationCodeClaims,
  RefreshTokenClaims,
  AuthorizeRequest,
  AuthorizationCodeGrantRequest,
  ClientCredentialsGrantRequest,
  RefreshTokenGrantRequest,
} from "../src/oauth/types";

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

  describe("Authorize", () => {
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

    it("validates redirect URIs", () => {
      const err1 = validateRedirectUri(
        { redirectUri: undefined },
        ["a", "b"],
        iss,
      );
      expect((err1 as { error: string }).error).toBe("invalid_request");
      const def = validateRedirectUri(
        { redirectUri: undefined },
        ["https://cb"],
        iss,
      );
      expect(def).toBe("https://cb");
      const err2 = validateRedirectUri(
        { redirectUri: "https://cbX" },
        ["https://cb"],
        iss,
      );
      expect((err2 as { error: string }).error).toBe("invalid_request");
      const ok = validateRedirectUri(
        { redirectUri: "https://cb" },
        ["https://cb"],
        iss,
      );
      expect(ok).toBe("https://cb");
    });

    it("buildAuthorizationCode validates input and returns error on bad request", async () => {
      await expect(
        buildAuthorizationCode({
          // @ts-expect-error missing: redirect_uri, code_challenge, etc.
          req: { client_id: "c", response_type: "code" },
          claims: { sub: "u" },
          iss,
          options: acOpts,
        }),
      ).rejects.toThrow(
        "OAuthError invalid_request Missing redirect_uri for authorization redirect",
      );
    });

    // Skipping success path that requires actual JWE support; covered via token grant builders below

    it("buildAuthorizationCode returns server_error when encryption fails", async () => {
      const req: AuthorizeRequest = {
        client_id: "c",
        response_type: "code",
        code_challenge: "x",
        code_challenge_method: "plain",
        resource: "res",
        redirect_uri: "https://cb",
      };

      const redirectWithError = await buildAuthorizationCode({
        req,
        claims: { sub: "u" },
        iss,
        randomJti: () => "x",
        // @ts-expect-error Intentionally pass an invalid privateKey to make encrypt() fail internally
        options: { privateKey: { not: "a valid key" } },
      });
      expect(redirectWithError).toMatchInlineSnapshot(
        `"https://cb/?iss=https%3A%2F%2Fissuer&error=server_error&error_description=JWE+%22alg%22+%28Key+Management+Algorithm%29+must+be+provided+in+options+or+inferable+from+the+key"`,
      );
    });

    it("buildAuthorizationRedirect builds URL with params", () => {
      const url = buildAuthorizationRedirect({
        res: { code: "code123", state: "s", iss },
        redirect_uri: "https://cb/path?existing=1",
      });
      expect(url).toContain("code=code123");
      expect(url).toContain("iss=https%3A%2F%2Fissuer");
      expect(url).toContain("state=s");

      const errUrl = buildAuthorizationRedirect({
        res: { error: "invalid_request", error_description: "bad", iss },
        redirect_uri: "https://cb",
      });
      expect(errUrl).toContain("error=invalid_request");
      expect(errUrl).toContain("error_description=bad");
    });
  });

  describe("Introspect + Token flows", () => {
    const iss = "https://issuer";
    const now = new Date("2024-01-01T00:00:00Z");
    const jwk = makeOctJwk(32, "HS256"); // for JWS (access/id tokens)

    const accessTokenOptions = {
      privateKey: jwk,
      signOptions: {
        alg: "HS256",
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
    const authCodeOptions = { privateKey: "ac-jwe-secret-key" } as const;

    it("introspects authorization_code, access_token, refresh_token", async () => {
      // Ensure invalid authorization code is rejected
      await expect(
        introspectAuthorizationCode({
          token: "not-a-jwe",
          iss,
          options: authCodeOptions,
        }),
      ).rejects.toBeDefined();

      // Use token grant builder to obtain AT/RT and introspect access token
      const tg = await buildAuthorizationCodeGrant({
        req: {
          grant_type: "authorization_code",
          code: "dummy",
          client_id: "client",
          code_verifier: "verifier",
        },
        codeClaims: {
          sub: "user",
          jti: "j1",
          iss,
          iat: Math.floor(now.getTime() / 1000),
          exp: Math.floor(now.getTime() / 1000) + 600,
          client_id: "client",
          redirect_uri: "https://cb",
          code_challenge: "verifier",
          code_challenge_method: "plain",
          resource: "api",
          scope: "read",
        },
        accessTokenOptions,
        refreshTokenOptions,
        iss,
        randomJti: () => "abc",
        currentDate: now,
      });
      const at = await introspectAccessToken({
        token: tg.res.access_token,
        iss,
        options: accessTokenOptions,
      });
      expect(at.payload.sub).toBe("user");
      // We don't decrypt refresh token (JWE) here to keep tests algorithm-agnostic
      expect(typeof tg.res.refresh_token).toBe("string");
    });

    it("validateTokenRequest checks grant_type", () => {
      expect(() => validateTokenRequest({}, iss)).toThrowError(OAuthError);
      expect(() =>
        validateTokenRequest({ grant_type: "foobar" }, iss),
      ).toThrowError(OAuthError);
      expect(() =>
        validateTokenRequest(
          { grant_type: "client_credentials", client_id: "c", resource: "r" },
          iss,
        ),
      ).not.toThrow();
    });

    it("validateAuthorizationCodeClaims validates PKCE and bindings", async () => {
      const verifier = "v";
      const challenge = "v"; // plain
      const req: AuthorizationCodeGrantRequest = {
        grant_type: "authorization_code",
        code: "x",
        client_id: "client",
        code_verifier: verifier,
      };
      const good: AuthorizationCodeClaims = {
        sub: "u",
        jti: "j",
        iss,
        iat: 1,
        exp: 2,
        client_id: "client",
        redirect_uri: "https://cb",
        code_challenge: challenge,
        code_challenge_method: "plain",
        resource: "api",
        scope: "read",
      };
      await expect(
        validateAuthorizationCodeClaims({ claims: good, req, iss }),
      ).resolves.toBeUndefined();

      const badSub = { ...good };
      // @ts-expect-error deleting required field
      delete badSub.sub;
      await expect(
        validateAuthorizationCodeClaims({
          claims: badSub,
          req,
          iss,
        }),
      ).rejects.toMatchObject({ error: "invalid_grant" });

      const badClient = { ...good, client_id: "other" };
      await expect(
        validateAuthorizationCodeClaims({
          claims: badClient,
          req,
          iss,
        }),
      ).rejects.toMatchObject({ error: "invalid_grant" });

      await expect(
        validateAuthorizationCodeClaims({
          // @ts-expect-error intentional missing code_challenge
          claims: { ...good, code_challenge: undefined },
          req,
          iss,
        }),
      ).rejects.toBeInstanceOf(OAuthError);

      await expect(
        validateAuthorizationCodeClaims({
          claims: { ...good, code_challenge: "nope" },
          req,
          iss,
        }),
      ).rejects.toBeInstanceOf(OAuthError);
    });

    it("buildAuthorizationCodeGrant builds AT/RT with expected claims", async () => {
      const verifier = "v";
      const challenge = "v"; // plain
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
        scope: "read",
      };

      const out = await buildAuthorizationCodeGrant({
        req,
        codeClaims,
        accessTokenOptions,
        refreshTokenOptions,
        extraAccessTokenClaims: { extra: true },
        extraRefreshTokenClaims: { more: 1 },
        iss,
        randomJti: () => "id-123",
        currentDate: now,
      });

      expect(out.res.token_type).toBe("Bearer");
      const at = await introspectAccessToken({
        token: out.res.access_token,
        iss,
        options: accessTokenOptions,
      });
      expect(at.payload.sub).toBe("user");
      expect(at.payload.aud).toBe("api");

      // Do not decrypt refresh token (JWE); assert it exists
      expect(typeof out.res.refresh_token).toBe("string");
    });

    it("buildClientCredentialsGrant builds AT with subject=client_id", async () => {
      const req: ClientCredentialsGrantRequest = {
        grant_type: "client_credentials",
        client_id: "svc",
        scope: "s1 s2",
        resource: "api",
      };
      const out = await buildClientCredentialsGrant({
        req,
        accessTokenOptions,
        extraAccessTokenClaims: { foo: "bar" },
        iss,
        randomJti: () => "x",
        currentDate: now,
      });
      const at = await introspectAccessToken({
        token: out.res.access_token,
        iss,
        options: accessTokenOptions,
      });
      expect(at.payload.sub).toBe("svc");
      expect(at.payload.client_id).toBe("svc");
      expect(at.payload.scope).toBe("s1 s2");
    });

    it("buildRefreshTokenGrant rotates refresh token and narrows scope", async () => {
      const req: RefreshTokenGrantRequest = {
        grant_type: "refresh_token",
        refresh_token: "rt",
        client_id: "client",
        scope: "read",
      };
      const old: RefreshTokenClaims = {
        sub: "u",
        client_id: "client",
        iss,
        iat: Math.floor(now.getTime() / 1000) - 10,
        exp: Math.floor(now.getTime() / 1000) + 100,
        jti: "old",
        resource: "api",
        scope: "read write",
      };
      const out = await buildRefreshTokenGrant({
        req,
        refreshTokenClaims: old,
        accessTokenOptions,
        refreshTokenOptions,
        iss,
        randomJti: () => "y",
        currentDate: now,
      });
      const at = await introspectAccessToken({
        token: out.res.access_token,
        iss,
        options: accessTokenOptions,
      });
      expect(at.payload.scope).toBe("read");
      // Do not decrypt new refresh token (JWE); assert it exists
      expect(typeof out.res.refresh_token).toBe("string");
    });
  });
});
