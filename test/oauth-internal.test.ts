import { describe, it, expect } from "vitest";
import {
  type AuthorizationCodeReturn,
  OAuthError,
  oauthOptionsDefaults,
  authorizationCodeDefaults,
  validateAuthorizationCodeRequest,
  buildAuthorizationCode,
  buildAuthorizationRedirect,
  issueAuthorizationCode,
} from "../src/oauth/internal";

describe("oauth/authorize", () => {
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
    it("respects custom expiresIn and currentDate", () => {
      const now = new Date("2025-09-10T12:00:00Z");
      const opts = {
        ...mockAuthBaseOptions,
        encryptOptions: {
          expiresIn: 123,
          currentDate: now,
        },
      };
      expect(authorizationCodeDefaults(opts)).toEqual({
        privateKey: "supersecret",
        encryptOptions: {
          expiresIn: 123,
          currentDate: now,
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

      const req = {
        response_type: "code",
        client_id: "client123",
        code_challenge: "challenge456",
      };
      const computedFromStorage = {
        ...req,
        redirect_uri: "https://example.com/callback",
        scope: "read",
      };

      expect(
        validateAuthorizationCodeRequest(computedFromStorage, mockOptions),
      ).toBeUndefined();
      // @ts-expect-error
      expect(validateAuthorizationCodeRequest({}, mockOptions)).toEqual({
        error: "invalid_request",
        error_description: "Invalid authorize request",
        state: undefined,
        iss: mockOptions.issuer,
      });
      // Invalid response_type
      const invalidResponseType = validateAuthorizationCodeRequest(
        { ...computedFromStorage, response_type: "token" },
        mockOptions,
      );
      expect(invalidResponseType).toBeDefined();
      expect(invalidResponseType).toHaveProperty(
        "error",
        "unsupported_response_type",
      );
      // Missing code_challenge
      const missingCodeChallenge = validateAuthorizationCodeRequest(
        // @ts-expect-error
        { ...computedFromStorage, code_challenge: undefined },
        mockOptions,
      );
      expect(missingCodeChallenge).toBeDefined();
      expect(missingCodeChallenge).toHaveProperty("error", "invalid_request");
      // Unsupported code_challenge_method
      const invalidCodeChallengeMethod = validateAuthorizationCodeRequest(
        // @ts-expect-error
        { ...computedFromStorage, code_challenge_method: "MD5" },
        mockOptions,
      );
      expect(invalidCodeChallengeMethod).toBeDefined();
      expect(invalidCodeChallengeMethod).toHaveProperty(
        "error",
        "invalid_request",
      );
    });
  });

  describe("buildAuthorizationCode", () => {
    it("returns error if sub is missing", async () => {
      const options = oauthOptions;
      const onAuthCodeReturn = {
        response_type: "code",
        client_id: "client123",
        code_challenge: "challenge456",
        redirect_uri: "https://example.com/callback",
        claims: {},
      };
      // @ts-expect-error
      const result = await buildAuthorizationCode(onAuthCodeReturn, options);
      expect(result).toHaveProperty("error", "invalid_request");
      expect(result).toHaveProperty("error_description");
    });

    it("returns AuthorizationCodeReturn if valid", async () => {
      const options = oauthOptions;
      const onAuthCodeReturn = {
        response_type: "code",
        client_id: "client123",
        code_challenge: "challenge456",
        redirect_uri: "https://example.com/callback",
        claims: { sub: "user1" },
      };
      const result = await buildAuthorizationCode(onAuthCodeReturn, options);
      expect(result).toHaveProperty("code");
      expect(result).toHaveProperty("state");
      expect(result).toHaveProperty("iss", options.issuer);
      expect(result).toHaveProperty("claims");
      expect((result as AuthorizationCodeReturn).claims).toHaveProperty(
        "sub",
        "user1",
      );
    });
  });

  describe("buildAuthorizationRedirect", () => {
    it("returns error if result is missing code and error", () => {
      const req = {
        response_type: "code",
        client_id: "client123",
        code_challenge: "challenge456",
        redirect_uri: "https://example.com/callback",
      };
      // @ts-expect-error
      const res = buildAuthorizationRedirect(req, {}, { issuer: "issuer" });
      expect(res).toHaveProperty("error", "server_error");
    });

    it("returns redirect URI with code", () => {
      const req = {
        response_type: "code",
        client_id: "client123",
        code_challenge: "challenge456",
        redirect_uri: "https://example.com/callback",
        state: "abc",
      };
      const result = {
        code: "thecode",
        state: "abc",
        iss: "issuer",
      };
      const uri = buildAuthorizationRedirect(req, result, { issuer: "issuer" });
      expect(uri).toContain("code=thecode");
      expect(uri).toContain("state=abc");
      expect(uri).toContain("iss=issuer");
    });

    it("returns redirect URI with error", () => {
      const req = {
        response_type: "code",
        client_id: "client123",
        code_challenge: "challenge456",
        redirect_uri: "https://example.com/callback",
        state: "abc",
      };
      const result = {
        error: "invalid_request",
        error_description: "desc",
        state: "abc",
        iss: "issuer",
      };
      const uri = buildAuthorizationRedirect(req, result, { issuer: "issuer" });
      expect(uri).toContain("error=invalid_request");
      expect(uri).toContain("error_description=desc");
      expect(uri).toContain("state=abc");
      expect(uri).toContain("iss=issuer");
    });
  });

  describe("issueAuthorizationCode", () => {
    it("throws if onAuthorizeRequest hook is missing", async () => {
      const options = { ...oauthOptions, hooks: undefined };
      await expect(issueAuthorizationCode(options)).rejects.toThrow(
        "Missing onAuthorizeReq hook",
      );
    });

    it("throws if redirect_uri is missing", async () => {
      const options = {
        ...oauthOptions,
        hooks: {
          onAuthorizeRequest: () => ({
            response_type: "code",
            client_id: "client123",
            code_challenge: "challenge456",
            claims: { sub: "user1" },
          }),
        },
      };
      // @ts-expect-error
      await expect(issueAuthorizationCode(options)).resolves.toStrictEqual({
        error: "invalid_request",
        error_description:
          "redirect_uri is missing and no registered redirect URI is available for this client",
        iss: options.issuer,
      });
    });

    it("returns redirect URI with error if hook throws", async () => {
      const options = {
        ...oauthOptions,
        hooks: {
          onAuthorizeRequest: () => {
            throw new OAuthError({
              error: "invalid_client",
              error_description: "Client not found",
            });
          },
        },
      };
      // @ts-expect-error
      const res = await issueAuthorizationCode(options);
      expect(res).toHaveProperty("error", "invalid_client");
      expect(res).toHaveProperty("error_description");
    });

    it("returns redirect URI with code if hook returns valid", async () => {
      const options = {
        ...oauthOptions,
        hooks: {
          onAuthorizeRequest: () => ({
            response_type: "code",
            client_id: "client123",
            code_challenge: "challenge456",
            redirect_uri: "https://example.com/callback",
            claims: { sub: "user1" },
          }),
        },
      };
      // @ts-expect-error
      const uri = await issueAuthorizationCode(options);
      expect(uri).toContain("code=");
      expect(uri).toContain("iss=");
    });
  });
});
