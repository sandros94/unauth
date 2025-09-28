import { describe, it, expect, vi, afterEach } from "vitest";
import { randomBytes } from "node:crypto";
import { base64UrlEncode } from "unsecure/utils";
import type { JWK_oct } from "unjwt";
import * as oauthProvider from "../src/oauth/provider";
import * as oidcUtils from "../src/oidc/provider/internal/utils";
import * as jws from "unjwt/jws";

vi.mock("unjwt/jws", () => ({
  sign: vi.fn(),
}));

import {
  idTokenDefaults,
  buildOIDCDiscoveryDocument,
  buildUserInfo,
  validateAuthorizeRequest as oidcValidateAuthorizeRequest,
  issueAuthorizationCode as oidcIssueAuthorizationCode,
  issueAuthorizationCodeGrant as oidcIssueAuthorizationCodeGrant,
  issueRefreshTokenGrant as oidcIssueRefreshTokenGrant,
  computeTokenHash,
} from "../src/oidc/provider";
import type {
  NormalizedAuthorizeInput,
  IssueAuthorizationCodeOptions,
  IssueTokenGrantOptions,
  NormalizedAuthorizationCodeGrantInput,
  NormalizedRefreshTokenGrantInput,
} from "../src/oidc/provider";

const makeOctJwk = (size = 32, alg?: string): JWK_oct => {
  const key = randomBytes(size);
  return { kty: "oct", k: base64UrlEncode(key), ...(alg ? { alg } : {}) };
};

const fixedDate = new Date("2024-01-01T00:00:00Z");

const buildOidcOptions = (
  overrides: Partial<IssueTokenGrantOptions> = {},
): IssueTokenGrantOptions => {
  const base: IssueTokenGrantOptions = {
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
    idTokenOptions: {
      privateKey: makeOctJwk(32, "HS256"),
      signOptions: {
        alg: "HS256",
      },
    },
    randomJti: () => "oidc-jti",
    currentDate: fixedDate,
  };
  return {
    ...base,
    ...overrides,
    authorizationCodeOptions: {
      ...base.authorizationCodeOptions,
      ...overrides.authorizationCodeOptions,
    },
    accessTokenOptions: {
      ...base.accessTokenOptions,
      ...overrides.accessTokenOptions,
    },
    refreshTokenOptions: {
      ...base.refreshTokenOptions,
      ...overrides.refreshTokenOptions,
    },
    idTokenOptions: {
      ...base.idTokenOptions,
      ...overrides.idTokenOptions,
    },
  };
};

afterEach(() => {
  vi.clearAllMocks();
  vi.restoreAllMocks();
});

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

  describe("Authorize helpers", () => {
    const redirectUri = "https://rp.example.com/callback";

    const baseRequest = {
      client_id: "client",
      response_type: "code" as const,
      code_challenge: "challenge",
      code_challenge_method: "S256" as const,
      redirect_uri: redirectUri,
      resource: "https://api",
      scope: "openid profile",
      state: "state-123",
      nonce: "nonce-123",
    } satisfies Parameters<typeof oidcValidateAuthorizeRequest>[0];

    it("requires openid scope", () => {
      const res = oidcValidateAuthorizeRequest({
        ...baseRequest,
        scope: "profile email",
      });
      expect(res.success).toBe(false);
      if (res.success) {
        throw new Error("Expected failure");
      }
      expect(res.error.error).toBe("invalid_request");
      expect(res.error.error_description).toMatch(/openid/);
    });

    it("requires S256 PKCE method", () => {
      const res = oidcValidateAuthorizeRequest({
        ...baseRequest,
        code_challenge_method: "plain",
      } as unknown as Parameters<typeof oidcValidateAuthorizeRequest>[0]);
      expect(res.success).toBe(false);
      if (res.success) {
        throw new Error("Expected failure");
      }
      expect(res.error.error_description).toMatch(/code_challenge_method/);
    });

    it("normalizes authorize request with nonce propagation", () => {
      const res = oidcValidateAuthorizeRequest(baseRequest);
      expect(res.success).toBe(true);
      if (!res.success) {
        throw new Error("Expected success");
      }
      expect(res.value.scope).toBe("openid profile");
      expect(res.value.code_challenge_method).toBe("S256");
      expect(res.value.nonce).toBe("nonce-123");
      expect(res.value.acExtraClaims).toEqual({ nonce: "nonce-123" });
    });

    it("issues authorization code while passing nonce to OAuth layer", async () => {
      const oauthSpy = vi
        .spyOn(oauthProvider, "issueAuthorizationCode")
        .mockResolvedValue({
          success: true,
          value: `${redirectUri}?code=oauth-code`,
        });
      const args: NormalizedAuthorizeInput = {
        ...baseRequest,
        subject: "user",
        resource: "https://api",
      };
      const options: IssueAuthorizationCodeOptions = {
        iss: "https://issuer.example.com",
        authorizationCodeOptions: {
          privateKey: "secret",
        },
      };
      const result = await oidcIssueAuthorizationCode(args, options);
      expect(result.success).toBe(true);
      if (!result.success) {
        throw new Error("Expected success");
      }
      expect(result.value).toBe(`${redirectUri}?code=oauth-code`);
      expect(oauthSpy).toHaveBeenCalled();
      const callArgs = oauthSpy.mock.calls[0]![0];
      expect(callArgs.acExtraClaims?.nonce).toBe("nonce-123");
      expect(callArgs.scope).toBe("openid profile");
      expect(callArgs.code_challenge_method).toBe("S256");
    });

    it("returns error redirect when scope validation fails", async () => {
      const oauthSpy = vi.spyOn(oauthProvider, "issueAuthorizationCode");
      const result = await oidcIssueAuthorizationCode(
        {
          ...baseRequest,
          subject: "user",
          scope: "profile",
        } as unknown as NormalizedAuthorizeInput,
        {
          iss: "https://issuer.example.com",
          authorizationCodeOptions: {
            privateKey: "secret",
          },
        },
      );
      expect(result.success).toBe(true);
      if (!result.success) {
        throw new Error("Expected redirect result");
      }
      const url = new URL(result.value);
      expect(url.searchParams.get("error")).toBe("invalid_request");
      expect(oauthSpy).not.toHaveBeenCalled();
    });
  });

  describe("Token helpers", () => {
    const baseAtClaims = {
      sub: "user",
      client_id: "client",
      iss: "https://issuer.example.com",
      iat: Math.floor(fixedDate.getTime() / 1000),
      exp: Math.floor(fixedDate.getTime() / 1000) + 3600,
      jti: "at-jti",
      aud: ["https://api"],
      scope: "openid profile",
    };

    it("issues authorization_code grant with ID token generation", async () => {
      const oauthSpy = vi
        .spyOn(oauthProvider, "issueAuthorizationCodeGrant")
        .mockResolvedValue({
          success: true,
          value: {
            access_token: "oauth-at",
            refresh_token: "oauth-rt",
            token_type: "Bearer",
            expires_in: 3600,
            scope: "openid profile",
          },
          artifacts: {
            accessTokenClaims: baseAtClaims,
            refreshTokenClaims: {
              sub: "user",
              client_id: "client",
              iss: "https://issuer.example.com",
              iat: Math.floor(fixedDate.getTime() / 1000),
              exp: Math.floor(fixedDate.getTime() / 1000) + 7200,
              jti: "rt-jti",
              resource: ["https://api"],
              scope: "openid profile",
              nonce: "nonce-123",
            },
          },
        });
      vi.spyOn(oidcUtils, "computeTokenHash").mockResolvedValue("at-hash");
      const signMock = vi.mocked(jws.sign);
      signMock.mockResolvedValueOnce("id-token");

      const args: NormalizedAuthorizationCodeGrantInput = {
        type: "authorization_code",
        client_id: "client",
        code: {
          sub: "user",
          client_id: "client",
          iss: "https://issuer.example.com",
          iat: Math.floor(fixedDate.getTime() / 1000) - 60,
          exp: Math.floor(fixedDate.getTime() / 1000) + 600,
          jti: "ac-jti",
          resource: ["https://api"],
          scope: "openid profile",
          code_challenge: "challenge",
          code_challenge_method: "S256",
          nonce: "nonce-123",
        },
        code_verifier: "verifier",
        refreshTokenExtraClaims: { custom: true },
        idTokenExtraClaims: { email: "user@example.com" },
      };

      const result = await oidcIssueAuthorizationCodeGrant(
        args,
        buildOidcOptions(),
      );
      expect(result.success).toBe(true);
      if (!result.success) {
        throw new Error("Expected success");
      }
      expect(oauthSpy).toHaveBeenCalled();
      const callArgs = oauthSpy.mock.calls[0]![0];
      expect(result.value).toMatchObject({
        access_token: "oauth-at",
        refresh_token: "oauth-rt",
        id_token: "id-token",
        scope: "openid profile",
      });
      expect(result.artifacts?.idTokenClaims).toMatchObject({
        nonce: "nonce-123",
        email: "user@example.com",
        at_hash: "at-hash",
      });
      expect(callArgs.refreshTokenExtraClaims).toEqual({
        custom: true,
        nonce: "nonce-123",
      });
      expect(signMock).toHaveBeenCalled();
    });

    it("propagates OAuth failures during authorization_code grant", async () => {
      vi.spyOn(oauthProvider, "issueAuthorizationCodeGrant").mockResolvedValue({
        success: false,
        error: {
          error: "invalid_grant",
          error_description: "bad",
        },
      });
      const result = await oidcIssueAuthorizationCodeGrant(
        {
          type: "authorization_code",
          client_id: "client",
          code: {
            sub: "user",
            client_id: "client",
            iss: "https://issuer.example.com",
            iat: Math.floor(fixedDate.getTime() / 1000),
            exp: Math.floor(fixedDate.getTime() / 1000) + 600,
            jti: "ac-jti",
            resource: "https://api",
            scope: "openid",
            code_challenge: "challenge",
            code_challenge_method: "S256",
          },
          code_verifier: "verifier",
        },
        buildOidcOptions(),
      );
      expect(result.success).toBe(false);
      if (result.success) {
        throw new Error("Expected failure");
      }
      expect(result.error.error).toBe("invalid_grant");
    });

    it("issues refresh_token grant and builds new ID token", async () => {
      const oauthSpy = vi
        .spyOn(oauthProvider, "issueRefreshTokenGrant")
        .mockResolvedValue({
          success: true,
          value: {
            access_token: "new-at",
            refresh_token: "new-rt",
            token_type: "Bearer",
            expires_in: 3600,
            scope: "openid",
          },
          artifacts: {
            accessTokenClaims: {
              ...baseAtClaims,
              scope: "openid",
            },
            refreshTokenClaims: {
              sub: "user",
              client_id: "client",
              iss: "https://issuer.example.com",
              iat: Math.floor(fixedDate.getTime() / 1000),
              exp: Math.floor(fixedDate.getTime() / 1000) + 7200,
              jti: "rt2-jti",
              resource: ["https://api"],
              scope: "openid",
              nonce: "nonce-789",
            },
          },
        });
      vi.spyOn(oidcUtils, "computeTokenHash").mockResolvedValue("hash-2");
      const signMock = vi.mocked(jws.sign);
      signMock.mockResolvedValueOnce("id-token-2");

      const args: NormalizedRefreshTokenGrantInput = {
        type: "refresh_token",
        client_id: "client",
        refresh_token: {
          sub: "user",
          client_id: "client",
          iss: "https://issuer.example.com",
          iat: Math.floor(fixedDate.getTime() / 1000) - 120,
          exp: Math.floor(fixedDate.getTime() / 1000) + 600,
          jti: "rt-old",
          resource: ["https://api"],
          scope: "openid profile",
          nonce: "nonce-789",
        },
        requested_scope: "openid",
        accessTokenExtraClaims: { extra: "at" },
        refreshTokenExtraClaims: { rotated: true },
      };

      const result = await oidcIssueRefreshTokenGrant(args, buildOidcOptions());
      expect(result.success).toBe(true);
      if (!result.success) {
        throw new Error("Expected success");
      }
      expect(oauthSpy).toHaveBeenCalled();
      const callArgs = oauthSpy.mock.calls[0]![0];
      expect(result.value).toMatchObject({
        access_token: "new-at",
        refresh_token: "new-rt",
        id_token: "id-token-2",
        scope: "openid",
      });
      expect(result.artifacts?.idTokenClaims).toMatchObject({
        nonce: "nonce-789",
        at_hash: "hash-2",
      });
      expect(callArgs.refreshTokenExtraClaims).toEqual({
        rotated: true,
        nonce: "nonce-789",
      });
      expect(signMock).toHaveBeenCalled();
    });

    it("propagates OAuth failures during refresh_token grant", async () => {
      vi.spyOn(oauthProvider, "issueRefreshTokenGrant").mockResolvedValue({
        success: false,
        error: {
          error: "invalid_grant",
          error_description: "bad",
        },
      });
      const result = await oidcIssueRefreshTokenGrant(
        {
          type: "refresh_token",
          client_id: "client",
          refresh_token: {
            sub: "user",
            client_id: "client",
            iss: "https://issuer.example.com",
            iat: Math.floor(fixedDate.getTime() / 1000),
            exp: Math.floor(fixedDate.getTime() / 1000) + 600,
            jti: "rt",
            resource: "https://api",
            scope: "openid",
          },
        },
        buildOidcOptions(),
      );
      expect(result.success).toBe(false);
      if (result.success) {
        throw new Error("Expected failure");
      }
      expect(result.error.error).toBe("invalid_grant");
    });
  });

  describe("Token utils", () => {
    it("computes at_hash for HS256", async () => {
      const hashValue = await computeTokenHash("token-value", "HS256");
      expect(hashValue).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(hashValue.length).toBeGreaterThan(10);
    });

    it("throws on unsupported algorithms", async () => {
      await expect(computeTokenHash("token", "RS1024")).rejects.toThrow(
        /Unsupported JWS alg/,
      );
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
