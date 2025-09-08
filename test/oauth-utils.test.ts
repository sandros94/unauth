import { describe, it, expect } from "vitest";
import type {
  AuthorizationCodeReturn,
  AuthorizationErrorResponse,
} from "../src/oauth/internal";
import {
  validatePKCE,
  isScopeSubset,
  authorizationCodeDefaults,
  oauthOptionsDefaults,
  validateAuthorizationCodeRequest,
  buildAuthorizationCode,
  buildAuthorizationRedirect,
} from "../src/oauth/internal";
import { hash } from "unsecure";

describe("oauth/utils", () => {
  const mockAuthBaseOptions = {
    privateKey: "supersecret",
  };
  const oauthOptions = oauthOptionsDefaults({
    issuer: "https://auth.example.com",
    availableScopes: ["read", "write"],
    authorizationCode: mockAuthBaseOptions,
    refreshToken: mockAuthBaseOptions,
    accessToken: { privateKey: { kty: "oct", k: "supersecret" } },
  });

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
      expect(isScopeSubset("read", ["read", "write"])).toBe(true);
      expect(isScopeSubset("read write", ["read", "write"])).toBe(true);
    });

    it("rejects superset and disjoint", () => {
      expect(isScopeSubset("read write admin", ["read", "write"])).toBe(false);
      expect(isScopeSubset("admin", ["read", "write"])).toBe(false);
    });
  });

  describe("authorizationCodeDefaults", () => {
    it("applies defaults", () => {
      expect(authorizationCodeDefaults(mockAuthBaseOptions)).toEqual({
        privateKey: "supersecret",
        encryptOptions: {
          expiresIn: 600,
          currentDate: expect.any(Date),
        },
      });
    });

    it("ignores unknown options", () => {
      const opts = {
        ...mockAuthBaseOptions,
        defaultScope: "read",
      };

      expect(authorizationCodeDefaults(opts)).toEqual({
        privateKey: "supersecret",
        encryptOptions: {
          expiresIn: 600,
          currentDate: expect.any(Date),
        },
      });
    });
  });

  describe("Authorization Code", () => {
    it("validates request", () => {
      const mockOptions = {
        issuer: "https://auth.example.com",
        defaultCodeChallengeMethod: "S256",
        availableScopes: ["read", "write"],
      } as const;

      const baseReq = {
        response_type: "code",
        client_id: "client123",
        code_challenge: "challenge456",
        redirect_uri: "https://example.com/callback",
      };
      const req = {
        ...baseReq,
        scope: "read",
      };

      expect(() =>
        validateAuthorizationCodeRequest(req, mockOptions),
      ).not.toThrow();
    });

    it("builds code and redirect", async () => {
      const authRes = await buildAuthorizationCode(oauthOptions, (opts) => {
        const mockOauthReq = {
          client_id: "client123",
          response_type: "code",
          code_challenge: "challenge456",
          state: "state123",
        };
        const oauthReq = validateAuthorizationCodeRequest(mockOauthReq, opts);
        return {
          ...oauthReq,
          claims: { sub: "user-789" },
        };
      }) as AuthorizationCodeReturn;

      expect(authRes).toEqual({
        code: expect.any(String),
        state: "state123",
        iss: "https://auth.example.com",
        claims: {
          sub: "user-789",
          client_id: "client123",
          code_challenge: "challenge456",
          code_challenge_method: "plain",
          jti: expect.any(String),
          exp: expect.any(Number),
          iat: expect.any(Number),
          iss: "https://auth.example.com",
        },
      });

      const expectedURL = new URL("https://example.com/callback");
      expectedURL.searchParams.set("iss", authRes.iss);
      expectedURL.searchParams.set("code", authRes.code);
      expectedURL.searchParams.set("state", authRes.state!);
      expect(
        buildAuthorizationRedirect(
          "https://auth.example.com",
          "https://example.com/callback",
          authRes,
        ),
      ).toBe(expectedURL.toString());
    });

    it("catch validation error during build and returns OAuth error response", async () => {
      const authResErr = await buildAuthorizationCode(oauthOptions, (opts) => {
        const mockOauthReq = {
          client_id: "client123",
          response_type: "code",
          state: "state123",
        };
        // @ts-expect-error intentionally missing code_challenge to trigger error
        const oauthReq = validateAuthorizationCodeRequest(mockOauthReq, opts);
        return {
          ...oauthReq,
          claims: { sub: "user-789" },
        };
      }) as AuthorizationErrorResponse;

      const expectedURL = new URL("https://example.com/callback");
      expectedURL.searchParams.set("iss", authResErr.iss!);
      expectedURL.searchParams.set("error", authResErr.error);
      expectedURL.searchParams.set(
        "error_description",
        authResErr.error_description!,
      );
      expectedURL.searchParams.set("state", authResErr.state!);
      expect(
        buildAuthorizationRedirect(
          "https://auth.example.com",
          "https://example.com/callback",
          authResErr,
        ),
      ).toBe(expectedURL.toString());
    });
  });
});
