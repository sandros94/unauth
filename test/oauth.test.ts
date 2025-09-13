import { describe, it, expect, beforeAll } from "vitest";
import type { JWK } from "unjwt";

import { OAuthProvider } from "../src/oauth";
import { generateJwk } from "../src/utils";

describe("OAuthProvider", () => {
  const now = new Date("2025-01-01T00:00:00Z");

  let at1Priv!: JWK;
  let at1Pub!: JWK;
  let at2Priv!: JWK;
  let at2Pub!: JWK;

  beforeAll(async () => {
    const k1 = await generateJwk("ES256", {
      params: { kid: "at-key-1" },
    });
    at1Priv = k1.privateKey;
    at1Pub = k1.publicKey;
    const k2 = await generateJwk("ES256", {
      params: { kid: "at-key-2" },
    });
    at2Priv = k2.privateKey;
    at2Pub = k2.publicKey;
  });

  it("constructs with defaults and exposes getters", () => {
    const provider = new OAuthProvider({
      issuer: "https://auth.example.com",
      availableScopes: ["read", "write"],
      defaultScope: "read",
      authorizationCode: { privateKey: "ac-secret" },
      refreshToken: { privateKey: "rt-secret" },
      accessToken: { privateKey: at1Priv },
      hooks: {
        onAuthorizeRequest: () => {
          throw new Error("not-used");
        },
        onTokenRequest: () => {
          throw new Error("not-used");
        },
      },
      jwks: [at1Pub],
      currentDate: now,
    });

    expect(provider.issuer).toBe("https://auth.example.com");
    expect(provider.availableScopes).toEqual(["read", "write"]);
    expect(provider.defaultScope).toBe("read");
    expect(provider.getPublicJwks()).toEqual({ keys: [at1Pub] });
    const info = provider.accessKeyInfo;
    expect(info).toMatchObject({ kid: "at-key-1", kty: at1Pub.kty });
  });

  it("manages JWKS: set, get by kid, and errors when active kid missing", () => {
    const provider = new OAuthProvider({
      issuer: "https://issuer.local",
      authorizationCode: { privateKey: "ac1" },
      refreshToken: { privateKey: "rt1" },
      accessToken: { privateKey: at1Priv },
      hooks: {
        onAuthorizeRequest: () => {
          throw new Error("noop");
        },
        onTokenRequest: () => {
          throw new Error("noop");
        },
      },
      currentDate: now,
    });

    // Initially undefined
    expect(provider.getPublicJwks()).toBeUndefined();

    // Setting JWKS without the active kid should throw
    expect(() => provider.setJwks([{ ...at2Pub }])).toThrow(
      /does not include the active signing key kid/i,
    );

    // Setting proper JWKS works; getPublicKeyByKid can find it
    provider.setJwks([at1Pub, at2Pub]);
    expect(provider.getPublicJwks()).toEqual({ keys: [at1Pub, at2Pub] });
    expect(provider.getPublicKeyByKid("at-key-1")).toEqual(at1Pub);
  });

  it("rotates access key with validations (with and without JWKS)", () => {
    const provider = new OAuthProvider({
      issuer: "https://issuer.rotate",
      authorizationCode: { privateKey: "ac" },
      refreshToken: { privateKey: "rt" },
      accessToken: { privateKey: at1Priv },
      hooks: {
        onAuthorizeRequest: () => {
          throw new Error("noop");
        },
        onTokenRequest: () => {
          throw new Error("noop");
        },
      },
      currentDate: now,
    });

    // Invalid new key
    expect(() =>
      provider.rotateAccessKey({ ...at2Priv, kid: undefined } as JWK),
    ).toThrow(/must include a kid/i);

    // No JWKS set and not provided -> error
    expect(() => provider.rotateAccessKey(at2Priv)).toThrow(/No JWKS set/i);

    // Provided JWKS missing new key -> error
    expect(() => provider.rotateAccessKey(at2Priv, [at1Pub])).toThrow(
      /does not include the new signing key kid/i,
    );

    // Provide proper JWKS -> success and key info updated
    provider.rotateAccessKey(at2Priv, [at1Pub, at2Pub]);
    expect(provider.accessKeyInfo.kid).toBe("at-key-2");

    // When JWKS already contains the key, rotation without passing JWKS works
    provider.rotateAccessKey(at1Priv, [at1Pub, at2Pub]); // set back both
    // Pre-set JWKS to include the next target key
    provider.setJwks([at1Pub, at2Pub]);
    provider.rotateAccessKey(at2Priv); // should not throw
    expect(provider.accessKeyInfo.kid).toBe("at-key-2");
  });

  it("rotates authorization and refresh keys with validation", () => {
    const provider = new OAuthProvider({
      issuer: "https://issuer.enc",
      authorizationCode: { privateKey: "ac" },
      refreshToken: { privateKey: "rt" },
      accessToken: { privateKey: at1Priv },
      hooks: {
        onAuthorizeRequest: () => {
          throw new Error("noop");
        },
        onTokenRequest: () => {
          throw new Error("noop");
        },
      },
      currentDate: now,
    });

    // Invalid key types
    // @ts-expect-error - wrong type
    expect(() => provider.rotateAuthorizationCodeKey(123)).toThrow(
      /Invalid encryption key/i,
    );
    // @ts-expect-error - wrong type
    expect(() => provider.rotateRefreshTokenKey({})).toThrow(
      /Invalid encryption key/i,
    );

    // Valid rotations
    provider.rotateAuthorizationCodeKey("new-ac");
    provider.rotateRefreshTokenKey("new-rt");
  });

  it("issues code, tokens and introspects via provider helpers (private and JWKS paths)", async () => {
    // We'll capture latest code for the token request hook
    const state = { code: "" };

    const provider = new OAuthProvider({
      issuer: "https://issuer.oauth",
      defaultScope: "read",
      authorizationCode: { privateKey: "ac-secret" },
      refreshToken: { privateKey: "rt-secret" },
      accessToken: {
        privateKey: at1Priv,
        verifyOptions: { typ: "at+jwt" },
      },
      jwks: [at1Pub],
      hooks: {
        onAuthorizeRequest: () => ({
          response_type: "code",
          client_id: "client123",
          code_challenge: "verifier-1", // plain method default
          redirect_uri: "https://app.example.com/cb",
          scope: "read",
          claims: { sub: "user1" },
        }),
        onTokenRequest: () => ({
          grant_type: "authorization_code",
          // code filled from latest authorize step
          code: state.code,
          client_id: "client123",
          code_verifier: "verifier-1",
        }),
      },
      currentDate: now,
    });

    // Issue authorization code (redirect URI)
    const redirect = await provider.issueAuthorizationCode();
    expect(typeof redirect).toBe("string");
    const url = new URL(redirect as string);
    expect(url.searchParams.get("iss")).toBe(provider.issuer);
    const code = url.searchParams.get("code");
    expect(code).toBeTruthy();
    state.code = code || "";

    // Introspect the code
    const acRes = await provider.introspectAuthorizationCode(code!);
    expect(acRes.active).toBe(true);
    expect(acRes.claims?.client_id).toBe("client123");

    // Issue access and refresh tokens
    const tokenRes = await provider.issueAccessToken();
    expect(tokenRes).toHaveProperty("access_token");
    expect(tokenRes).toHaveProperty("refresh_token");
    // Introspect with private key path (no JWKS yet)
    const atActive = await provider.introspectAccessToken(
      (tokenRes as any).access_token,
    );
    expect(atActive.active).toBe(true);
    const rtActive = await provider.introspectRefreshToken(
      (tokenRes as any).refresh_token,
    );
    expect(rtActive.active).toBe(true);

    // Negative paths for introspections
    expect((await provider.introspectAuthorizationCode("bad")).active).toBe(
      false,
    );
    expect((await provider.introspectAccessToken("bad")).active).toBe(false);
    expect((await provider.introspectRefreshToken("bad")).active).toBe(false);
  });

  it("builds discovery document with defaults and overrides", () => {
    const provider = new OAuthProvider({
      issuer: "https://issuer.disco/",
      authorizationCode: { privateKey: "ac" },
      refreshToken: { privateKey: "rt" },
      accessToken: { privateKey: at1Priv },
      jwks: [at1Pub],
      hooks: {
        onAuthorizeRequest: () => {
          throw new Error("noop");
        },
        onTokenRequest: () => {
          throw new Error("noop");
        },
      },
      currentDate: now,
    });

    const doc = provider.getDiscoveryDocument({ scopes_supported: ["read"] });
    expect(doc.issuer).toBe("https://issuer.disco"); // trailing slash trimmed
    expect(doc.authorization_endpoint).toBe("https://issuer.disco/authorize");
    expect(doc.token_endpoint).toBe("https://issuer.disco/token");
    expect(doc.jwks_uri).toBe("https://issuer.disco/.well-known/jwks.json");
    expect(doc.scopes_supported).toEqual(["read"]);

    const doc2 = provider.getDiscoveryDocument({
      authorization_endpoint: "https://a/custom/authz",
      token_endpoint: "https://a/custom/token",
      jwks_uri: "https://a/custom/jwks",
      introspection_endpoint: "https://a/custom/intro",
      response_types_supported: ["code"],
      default_scope: "read",
    });
    expect(doc2.authorization_endpoint).toBe("https://a/custom/authz");
    expect(doc2.introspection_endpoint).toBe("https://a/custom/intro");
    expect(doc2.default_scope).toBe("read");
  });
});
