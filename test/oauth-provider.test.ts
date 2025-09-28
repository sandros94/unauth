import { describe, it, expect, vi, afterEach } from "vitest";
import { randomBytes } from "node:crypto";
import { base64UrlEncode } from "unsecure/utils";
import type { JWK_oct } from "unjwt";
import * as jwe from "unjwt/jwe";
import * as jws from "unjwt/jws";

vi.mock("unjwt/jwe", () => ({
  encrypt: vi.fn(),
}));
vi.mock("unjwt/jws", () => ({
  sign: vi.fn(),
}));

import {
  OAuthError,
  authorizationCodeDefaults,
  refreshTokenDefaults,
  accessTokenDefaults,
  DEFAULTS_OPTIONS,
  buildOAuthDiscoveryDocument,
  validateRedirectUri,
  validateAuthorizeRequest,
  buildAuthorizationRedirect,
  issueAuthorizationCode,
  validatePKCE,
  isScopeSubset,
  validateTokenRequest,
  issueAuthorizationCodeGrant,
  issueClientCredentialsGrant,
  issueRefreshTokenGrant,
} from "../src/core/oauth/provider";
import type {
  NormalizedAuthorizationCodeGrantInput,
  NormalizedClientCredentialsGrantInput,
  NormalizedRefreshTokenGrantInput,
  IssueTokenOptions,
} from "../src/core/oauth/provider";

// Helpers

const makeOctJwk = (size = 32, alg?: string): JWK_oct => {
  const key = randomBytes(size);
  // intentionally mocking keys instead of using unjwt's generateKey
  return { kty: "oct", k: base64UrlEncode(key), ...(alg ? { alg } : {}) };
};

const fixedDate = new Date("2024-01-01T00:00:00Z");

const buildTokenOptions = (
  overrides: Partial<IssueTokenOptions> = {},
): IssueTokenOptions => {
  const base: IssueTokenOptions = {
    iss: "https://issuer.example.com",
    authorizationCodeOptions: {
      privateKey: "ac-secret",
    },
    accessTokenOptions: {
      privateKey: makeOctJwk(32, "HS256"),
      signOptions: {
        alg: "HS256",
      },
    },
    refreshTokenOptions: {
      privateKey: "rt-secret",
    },
    randomJti: () => "test-jti",
    currentDate: fixedDate,
  };
  return {
    ...base,
    ...overrides,
    accessTokenOptions: {
      ...base.accessTokenOptions,
      ...overrides.accessTokenOptions,
    },
    refreshTokenOptions: {
      ...base.refreshTokenOptions,
      ...overrides.refreshTokenOptions,
    },
    authorizationCodeOptions: {
      ...base.authorizationCodeOptions,
      ...overrides.authorizationCodeOptions,
    },
  };
};

afterEach(() => {
  vi.clearAllMocks();
  vi.restoreAllMocks();
});

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

  describe("Authorize helpers", () => {
    const redirectUri = "https://app.example.com/callback";

    it("returns registered redirect when request omits redirect_uri", () => {
      const res = validateRedirectUri(undefined, redirectUri);
      expect(res).toEqual({ success: true, value: redirectUri });
    });

    it("rejects missing redirect when multiple URIs are registered", () => {
      const res = validateRedirectUri(undefined, [redirectUri, "https://b"]);
      expect(res.success).toBe(false);
      if (res.success) {
        throw new Error("Expected failure");
      }
      expect(res.error.error).toBe("invalid_request");
      expect(res.error.error_description).toMatch(/Missing redirect_uri/);
    });

    it("validates provided redirect against allowed list", () => {
      const res = validateRedirectUri(redirectUri, [
        "https://other",
        redirectUri,
      ]);
      expect(res.success).toBe(true);
      if (!res.success) {
        throw new Error("Expected success");
      }
      expect(res.value).toBe(redirectUri);
    });

    it("rejects unknown redirect URIs", () => {
      const res = validateRedirectUri("https://evil", redirectUri);
      expect(res.success).toBe(false);
      if (res.success) {
        throw new Error("Expected failure");
      }
      expect(res.error.error).toBe("invalid_request");
      expect(res.error.error_description).toBe("Invalid redirect_uri");
    });

    it("normalizes authorize request payload", () => {
      const res = validateAuthorizeRequest({
        client_id: "abc",
        response_type: "code",
        redirect_uri: redirectUri,
        code_challenge: "challenge",
        code_challenge_method: "S256",
        resource: "https://api",
        scope: "read",
        state: "state123",
        extra: "claim",
      });
      expect(res.success).toBe(true);
      if (!res.success) {
        throw new Error("Expected success");
      }
      expect(res.value).toEqual(
        expect.objectContaining({
          client_id: "abc",
          code_challenge: "challenge",
          code_challenge_method: "S256",
          resource: "https://api",
          scope: "read",
          state: "state123",
        }),
      );
      expect(res.value.acExtraClaims).toEqual({ extra: "claim" });
    });

    it("fails when response_type differs from code", () => {
      const res = validateAuthorizeRequest({
        client_id: "abc",
        response_type: "token",
        code_challenge: "challenge",
        code_challenge_method: "S256",
        redirect_uri: redirectUri,
        resource: "https://api",
      } as unknown as Parameters<typeof validateAuthorizeRequest>[0]);
      expect(res.success).toBe(false);
      if (res.success) {
        throw new Error("Expected failure");
      }
      expect(res.error.error).toBe("unsupported_response_type");
    });

    it("fails when PKCE challenge or resource missing", () => {
      const res = validateAuthorizeRequest({
        client_id: "abc",
        response_type: "code",
        code_challenge: "",
        code_challenge_method: "S256",
        redirect_uri: redirectUri,
        resource: "",
      });
      expect(res.success).toBe(false);
      if (res.success) {
        throw new Error("Expected failure");
      }
      expect(res.error.error).toBe("invalid_request");
    });

    it("builds successful authorization redirect with code", () => {
      const res = buildAuthorizationRedirect(
        redirectUri,
        "auth-code",
        undefined,
        "state123",
        "https://issuer",
      );
      expect(res.success).toBe(true);
      if (!res.success) {
        throw new Error("Expected success");
      }
      const url = new URL(res.value);
      expect(url.pathname).toBe("/callback");
      expect(url.searchParams.get("code")).toBe("auth-code");
      expect(url.searchParams.get("state")).toBe("state123");
      expect(url.searchParams.get("iss")).toBe("https://issuer");
      expect(res.warnings).toBeUndefined();
    });

    it("propagates errors into redirect when code generation fails", () => {
      const error = {
        error: "invalid_request" as const,
        error_description: "boom",
      };
      const res = buildAuthorizationRedirect(
        redirectUri,
        undefined,
        error,
        "state",
        "https://issuer",
      );
      expect(res.success).toBe(true);
      if (!res.success) {
        throw new Error("Expected success");
      }
      const url = new URL(res.value);
      expect(url.searchParams.get("error")).toBe("invalid_request");
      expect(url.searchParams.get("error_description")).toBe("boom");
      expect(res.warnings?.error).toBe("invalid_request");
    });

    it("rejects build redirect when redirect_uri missing", () => {
      const res = buildAuthorizationRedirect(
        "",
        "code",
        undefined,
        "state",
        "https://issuer",
      );
      expect(res.success).toBe(false);
      if (res.success) {
        throw new Error("Expected failure");
      }
      expect(res.error.error_description).toBe(
        "Missing redirect_uri for authorization redirect",
      );
    });

    it("issues authorization code and returns redirect URL", async () => {
      const encryptMock = vi.mocked(jwe.encrypt);
      encryptMock.mockResolvedValueOnce("mock-ac-code");
      const result = await issueAuthorizationCode(
        {
          client_id: "client",
          subject: "user",
          redirect_uri: redirectUri,
          code_challenge: "challenge",
          code_challenge_method: "plain",
          resource: "https://api",
          state: "state123",
          scope: "read",
        },
        {
          iss: "https://issuer",
          authorizationCodeOptions: {
            privateKey: "secret",
          },
          randomJti: () => "jti-123",
          currentDate: new Date("2024-01-01T00:00:00Z"),
        },
      );
      expect(result.success).toBe(true);
      if (!result.success) {
        throw new Error("Expected success");
      }
      const url = new URL(result.value);
      expect(url.searchParams.get("code")).toBe("mock-ac-code");
      expect(result.artifacts).toEqual(
        expect.objectContaining({
          sub: "user",
          iss: "https://issuer",
          client_id: "client",
          code_challenge: "challenge",
          resource: "https://api",
        }),
      );
      expect(encryptMock).toHaveBeenCalledTimes(1);
    });

    it("surfaces error redirect when authorization code encryption fails", async () => {
      const encryptMock = vi.mocked(jwe.encrypt);
      encryptMock.mockRejectedValueOnce(new Error("kaboom"));
      const result = await issueAuthorizationCode(
        {
          client_id: "client",
          subject: "user",
          redirect_uri: redirectUri,
          code_challenge: "challenge",
          code_challenge_method: "plain",
          resource: "https://api",
          state: "mystate",
        },
        {
          iss: "https://issuer",
          authorizationCodeOptions: {
            privateKey: "secret",
          },
          randomJti: () => "jti-error",
          currentDate: new Date("2024-01-01T00:00:00Z"),
        },
      );
      expect(result.success).toBe(true);
      if (!result.success) {
        throw new Error("Expected success");
      }
      const url = new URL(result.value);
      expect(url.searchParams.get("error")).toBe("server_error");
      expect(url.searchParams.get("state")).toBe("mystate");
      expect(result.artifacts).toBeUndefined();
      expect(result.warnings?.error_description).toBe(
        "Failed to generate authorization code",
      );
    });

    it("rejects issuing authorization code when subject missing", async () => {
      const result = await issueAuthorizationCode(
        {
          client_id: "client",
          subject: "",
          redirect_uri: redirectUri,
          code_challenge: "challenge",
          code_challenge_method: "plain",
          resource: "https://api",
        },
        {
          iss: "https://issuer",
          authorizationCodeOptions: {
            privateKey: "secret",
          },
        },
      );
      expect(result.success).toBe(false);
      if (result.success) {
        throw new Error("Expected failure");
      }
      expect(result.error.error_description).toMatch(/Missing subject/);
    });
  });

  describe("Token helpers", () => {
    const makeAuthCodeClaims = () => ({
      sub: "user",
      client_id: "client",
      iss: "https://issuer.example.com",
      iat: Math.floor(fixedDate.getTime() / 1000),
      exp: Math.floor(fixedDate.getTime() / 1000) + 600,
      jti: "ac-jti",
      resource: ["https://api"],
      scope: "read",
      code_challenge: "verifier",
      code_challenge_method: "plain" as const,
    });

    it("normalizes authorization_code token grant requests", () => {
      const res = validateTokenRequest({
        grant_type: "authorization_code",
        client_id: "client",
        code: "abc",
        code_verifier: "verifier",
        accessTokenExtraClaims: { foo: "bar" },
        refreshTokenExtraClaims: { baz: "qux" },
      });
      expect(res.success).toBe(true);
      if (!res.success) {
        throw new Error("Expected success");
      }
      expect(res.value).toEqual(
        expect.objectContaining({
          grant_type: "authorization_code",
          client_id: "client",
          code: "abc",
          code_verifier: "verifier",
          accessTokenExtraClaims: { foo: "bar" },
          refreshTokenExtraClaims: { baz: "qux" },
        }),
      );
    });

    it("rejects token requests lacking client binding", () => {
      const res = validateTokenRequest({
        grant_type: "client_credentials",
        client_id: "" as unknown as string,
        resource: "https://api",
      });
      expect(res.success).toBe(false);
      if (res.success) {
        throw new Error("Expected failure");
      }
      expect(res.error.error).toBe("invalid_request");
      expect(res.error.error_description).toMatch(/client_id/);
    });

    it("rejects unsupported grant types", () => {
      const res = validateTokenRequest({
        grant_type: "password",
        client_id: "client",
      } as unknown as Parameters<typeof validateTokenRequest>[0]);
      expect(res.success).toBe(false);
      if (res.success) {
        throw new Error("Expected failure");
      }
      expect(res.error.error).toBe("unsupported_grant_type");
    });

    it("issues authorization_code grant with access and refresh tokens", async () => {
      const signMock = vi.mocked(jws.sign);
      signMock.mockResolvedValueOnce("signed-at");
      const encryptMock = vi.mocked(jwe.encrypt);
      encryptMock.mockResolvedValueOnce("encrypted-rt");
      const args: NormalizedAuthorizationCodeGrantInput = {
        grant_type: "authorization_code",
        client_id: "client",
        code: makeAuthCodeClaims(),
        code_verifier: "verifier",
        accessTokenExtraClaims: { extra: "ac" },
        refreshTokenExtraClaims: { extra: "rt" },
      };
      const result = await issueAuthorizationCodeGrant(
        args,
        buildTokenOptions(),
      );
      expect(result.success).toBe(true);
      if (!result.success) {
        throw new Error("Expected success");
      }
      expect(result.value).toMatchObject({
        access_token: "signed-at",
        refresh_token: "encrypted-rt",
        token_type: "Bearer",
        scope: "read",
      });
      expect(result.artifacts?.accessTokenClaims).toMatchObject({
        sub: "user",
        aud: ["https://api"],
        client_id: "client",
        scope: "read",
      });
      expect(result.artifacts?.refreshTokenClaims).toMatchObject({
        resource: ["https://api"],
        scope: "read",
      });
      expect(signMock).toHaveBeenCalledWith(
        expect.objectContaining({ sub: "user" }),
        expect.any(Object),
        expect.objectContaining({
          protectedHeader: expect.objectContaining({ typ: "at+jwt" }),
        }),
      );
      expect(encryptMock).toHaveBeenCalledWith(
        expect.objectContaining({ sub: "user" }),
        expect.any(String),
        expect.objectContaining({
          protectedHeader: expect.objectContaining({ typ: "rt+jwt" }),
        }),
      );
    });

    it("rejects authorization_code grant when PKCE fails", async () => {
      const result = await issueAuthorizationCodeGrant(
        {
          grant_type: "authorization_code",
          client_id: "client",
          code: {
            ...makeAuthCodeClaims(),
            code_challenge: "different",
          },
          code_verifier: "verifier",
        },
        buildTokenOptions(),
      );
      expect(result.success).toBe(false);
      if (result.success) {
        throw new Error("Expected failure");
      }
      expect(result.error.error).toBe("invalid_grant");
      expect(result.error.error_description).toMatch(/PKCE/);
    });

    it("issues client_credentials grant with access token only", async () => {
      const signMock = vi.mocked(jws.sign);
      signMock.mockResolvedValueOnce("signed-cc");
      const args: NormalizedClientCredentialsGrantInput = {
        grant_type: "client_credentials",
        client_id: "client",
        resource: "https://api",
        scope: "write",
        accessTokenExtraClaims: { tier: "gold" },
      };
      const result = await issueClientCredentialsGrant(
        args,
        buildTokenOptions(),
      );
      expect(result.success).toBe(true);
      if (!result.success) {
        throw new Error("Expected success");
      }
      expect(result.value).toEqual(
        expect.objectContaining({
          access_token: "signed-cc",
          refresh_token: undefined,
          scope: "write",
        }),
      );
      expect(result.artifacts?.accessTokenClaims).toMatchObject({
        sub: "client",
        aud: "https://api",
        scope: "write",
        tier: "gold",
      });
      expect(signMock).toHaveBeenCalledTimes(1);
    });

    it("issues refresh_token grant, rotating tokens and narrowing scope", async () => {
      const signMock = vi.mocked(jws.sign);
      signMock.mockResolvedValueOnce("new-at");
      const encryptMock = vi.mocked(jwe.encrypt);
      encryptMock.mockResolvedValueOnce("new-rt");
      const args: NormalizedRefreshTokenGrantInput = {
        grant_type: "refresh_token",
        client_id: "client",
        refresh_token: {
          sub: "user",
          client_id: "client",
          iss: "https://issuer.example.com",
          iat: Math.floor(fixedDate.getTime() / 1000) - 60,
          exp: Math.floor(fixedDate.getTime() / 1000) + 600,
          jti: "rt-jti",
          resource: ["https://api"],
          scope: "read write",
          nonce: "nonce-123",
        },
        requested_scope: "read",
        accessTokenExtraClaims: { audience: "internal" },
        refreshTokenExtraClaims: { rotated: true },
      };
      const result = await issueRefreshTokenGrant(args, buildTokenOptions());
      expect(result.success).toBe(true);
      if (!result.success) {
        throw new Error("Expected success");
      }
      expect(result.value).toMatchObject({
        access_token: "new-at",
        refresh_token: "new-rt",
        scope: "read",
        token_type: "Bearer",
      });
      expect(result.artifacts?.accessTokenClaims).toMatchObject({
        scope: "read",
        audience: "internal",
      });
      expect(result.artifacts?.refreshTokenClaims).toMatchObject({
        scope: "read",
        rotated: true,
      });
      expect(signMock).toHaveBeenCalledTimes(1);
      expect(encryptMock).toHaveBeenCalledTimes(1);
    });

    it("rejects refresh_token grant when requested scope exceeds original", async () => {
      const result = await issueRefreshTokenGrant(
        {
          grant_type: "refresh_token",
          client_id: "client",
          refresh_token: {
            sub: "user",
            client_id: "client",
            iss: "https://issuer.example.com",
            iat: Math.floor(fixedDate.getTime() / 1000) - 60,
            exp: Math.floor(fixedDate.getTime() / 1000) + 600,
            jti: "rt-jti",
            resource: "https://api",
            scope: "read",
          },
          requested_scope: "admin",
        },
        buildTokenOptions(),
      );
      expect(result.success).toBe(false);
      if (result.success) {
        throw new Error("Expected failure");
      }
      expect(result.error.error).toBe("invalid_scope");
    });
  });
});
