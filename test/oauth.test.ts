import { describe, it, expect, vi } from "vitest";
import { generateKey } from "unjwt/jwk";
import { type JWTClaims, verify } from "unjwt/jws";

import { OAuthProvider } from "../src/oauth/service";

describe("OAuthProvider", async () => {
  const issuer = "https://as.example";
  const accessKey = await generateKey("HS256", { toJWK: { kid: "acc1" } });
  const refreshSecret = "refresh-secret"; // symmetric secret for JWE

  const provider = new OAuthProvider({
    issuer,
    accessToken: { privateKey: accessKey },
    refreshToken: { privateKey: refreshSecret },
    defaultScope: "read write",
    availableScopes: ["read", "write", "admin"],
  });

  it("exposes basic config and key info", () => {
    expect(provider.issuer).toBe(issuer);
    expect(provider.availableScopes).toEqual(["read", "write", "admin"]);
    expect(provider.defaultScope).toBe("read write");
    expect(provider.accessKeyInfo.kid).toBe("acc1");
  });

  it("authorize -> token (authorization_code) end-to-end with PKCE and resource to aud", async () => {
    const client_id = "client-123";
    const redirect_uri = "https://client.example/cb";
    const code_verifier = "verifier123";
    const code_challenge = code_verifier; // plain
    const resource = "https://api.example";

    const { code, state } = await provider.authorize(
      {
        response_type: "code",
        client_id,
        redirect_uri,
        scope: "read",
        resource,
        code_challenge,
        code_challenge_method: "plain",
        state: "xyz",
      },
      async () => ({ sub: "user-42" }),
    );

    expect(typeof code).toBe("string");
    expect(state).toBe("xyz");

    const url = provider.buildAuthorizeRedirect(
      "https://client.example/cb?foo=1",
      { code, state },
      { iss: issuer },
    );
    const u = new URL(url);
    expect(u.searchParams.get("code")).toBeDefined();
    expect(u.searchParams.get("state")).toBe("xyz");
    expect(u.searchParams.get("iss")).toBe(issuer);

    const onCodeUsed = vi.fn();
    const onAuth = vi.fn();
    const token = await provider.tokenAuthorizationCode(
      {
        grant_type: "authorization_code",
        client_id,
        code,
        code_verifier,
        redirect_uri,
      },
      async () => ({
        accessTokenClaims: { extra: "yes" },
        refreshTokenClaims: {},
        onCodeUsed,
        onAuthenticateClient: onAuth,
      }),
    );

    expect(token).toHaveProperty("access_token");
    expect(token).toHaveProperty("refresh_token");
    expect(token.token_type).toBe("Bearer");
    expect(token.scope).toBe("read");
    expect(typeof token.expires_in).toBe("number");
    expect(onCodeUsed).toHaveBeenCalledTimes(1);
    expect(onAuth).toHaveBeenCalledTimes(1);

    const { payload } = await verify<JWTClaims>(token.access_token, accessKey);
    expect(payload.iss).toBe(issuer);
    expect(payload.scope).toBe("read");
    expect(payload.aud).toBe(resource);
    expect(payload.azp).toBe(client_id);
    expect(payload.client_id).toBe(client_id);
    expect(payload.sub).toBe("user-42");
    expect(payload.extra).toBe("yes");

    const a1 = await provider.introspectAccessToken(token.access_token);
    expect(a1.active).toBe(true);
    expect(a1.claims?.iss).toBe(issuer);

    const r1 = await provider.introspectRefreshToken(token.refresh_token!);
    expect(r1.active).toBe(true);
    expect(r1.claims?.iss).toBe(issuer);
  });

  it("tokenAuthorizationCode rejects on PKCE, client_id and redirect_uri mismatches", async () => {
    const client_id = "c1";
    const redirect_uri = "https://cb";
    const { code } = await provider.authorize(
      {
        response_type: "code",
        client_id,
        redirect_uri,
        scope: "read",
        code_challenge: "abc",
        code_challenge_method: "plain",
      },
      async () => ({ sub: "u" }),
    );

    await expect(
      provider.tokenAuthorizationCode(
        {
          grant_type: "authorization_code",
          client_id,
          code,
          code_verifier: "wrong",
          redirect_uri,
        },
        async () => ({ accessTokenClaims: {}, refreshTokenClaims: {} }),
      ),
    ).rejects.toThrow(/Invalid PKCE/);

    // client_id mismatch
    await expect(
      provider.tokenAuthorizationCode(
        {
          grant_type: "authorization_code",
          client_id: "other",
          code,
          code_verifier: "abc",
          redirect_uri,
        },
        async () => ({ accessTokenClaims: {}, refreshTokenClaims: {} }),
      ),
    ).rejects.toThrow(/Invalid client_id/);

    // redirect_uri mismatch
    await expect(
      provider.tokenAuthorizationCode(
        {
          grant_type: "authorization_code",
          client_id,
          code,
          code_verifier: "abc",
          redirect_uri: "https://other",
        },
        async () => ({ accessTokenClaims: {}, refreshTokenClaims: {} }),
      ),
    ).rejects.toThrow(/Invalid redirect_uri/);

    // redirect_uri supplied but not present in code
    const { code: code2 } = await provider.authorize(
      {
        response_type: "code",
        client_id,
        redirect_uri: "https://no-use", // will be embedded in code
        scope: "read",
        code_challenge: "v",
        code_challenge_method: "plain",
      },
      async () => ({ sub: "u" }),
    );
    await expect(
      provider.tokenAuthorizationCode(
        {
          grant_type: "authorization_code",
          client_id,
          code: code2,
          code_verifier: "v",
          redirect_uri: "https://different",
        },
        async () => ({ accessTokenClaims: {}, refreshTokenClaims: {} }),
      ),
    ).rejects.toThrow(/Invalid redirect_uri/);
  });

  it("refresh token flow enforces scope subset and updates aud", async () => {
    const client_id = "client-r";
    const { code } = await provider.authorize(
      {
        response_type: "code",
        client_id,
        redirect_uri: "https://cb",
        scope: "read write",
        resource: "https://res1",
        code_challenge: "v",
        code_challenge_method: "plain",
      },
      async () => ({ sub: "user-r" }),
    );

    const initial = await provider.tokenAuthorizationCode(
      {
        grant_type: "authorization_code",
        client_id,
        code,
        code_verifier: "v",
        redirect_uri: "https://cb",
      },
      async () => ({ accessTokenClaims: {}, refreshTokenClaims: {} }),
    );

    // Narrow scope is ok
    const used = vi.fn();
    const next = await provider.tokenRefreshToken(
      {
        grant_type: "refresh_token",
        refresh_token: initial.refresh_token!,
        client_id,
        scope: "read",
        resource: "https://res2",
      },
      async () => ({
        accessTokenClaims: {},
        refreshTokenClaims: {},
        onRefreshUsed: used,
      }),
    );
    expect(used).toHaveBeenCalledTimes(1);
    const { payload } = await verify<JWTClaims>(next.access_token, accessKey);
    expect(payload.scope).toBe("read");
    expect(payload.aud).toBe("https://res2");

    // Superset is rejected
    await expect(
      provider.tokenRefreshToken(
        {
          grant_type: "refresh_token",
          refresh_token: initial.refresh_token!,
          client_id,
          scope: "read write admin",
        },
        async () => ({ accessTokenClaims: {}, refreshTokenClaims: {} }),
      ),
    ).rejects.toThrow(/Invalid scope/);
  });

  it("client_credentials requires cb and issues at+jwt with aud and optional client_id", async () => {
    await expect(
      // @ts-expect-error deliberately missing cb
      provider.tokenClientCredentials({ grant_type: "client_credentials" }),
    ).rejects.toThrow(/Client authentication required/);

    const out = await provider.tokenClientCredentials(
      {
        grant_type: "client_credentials",
        scope: "read",
        aud: "https://svc",
        client_id: "c1",
      },
      async () => ({ sub: "c1", scope: "read" }),
    );
    const { payload, protectedHeader } = await verify<JWTClaims>(
      out.access_token,
      accessKey,
    );
    expect(protectedHeader.typ).toBe("at+jwt");
    expect(payload.aud).toBe("https://svc");
    expect(payload.client_id).toBe("c1");
    expect(payload.scope).toBe("read");
  });

  it("introspect returns inactive for tampered tokens", async () => {
    const bad = "x." + "y." + "z"; // malformed
    const acc = await provider.introspectAccessToken(bad);
    expect(acc.active).toBe(false);
    const ref = await provider.introspectRefreshToken(bad);
    expect(ref.active).toBe(false);
  });

  it("revoke extracts jti and invokes hook; invalid tokens are ignored", async () => {
    const client_id = "client-rvk";
    const { code } = await provider.authorize(
      {
        response_type: "code",
        client_id,
        redirect_uri: "https://cb",
        scope: "read",
        code_challenge: "v",
        code_challenge_method: "plain",
      },
      async () => ({ sub: "user" }),
    );
    const issued = await provider.tokenAuthorizationCode(
      {
        grant_type: "authorization_code",
        client_id,
        code,
        code_verifier: "v",
        redirect_uri: "https://cb",
      },
      async () => ({
        accessTokenClaims: { aud: "https://rvk" },
        refreshTokenClaims: {},
      }),
    );

    const hook = vi.fn();
    await provider.revoke(issued.access_token, "access", { onRevoke: hook });
    expect(hook).toHaveBeenCalledTimes(1);

    const hook2 = vi.fn();
    await provider.revoke(issued.refresh_token!, "refresh", {
      onRevoke: hook2,
    });
    expect(hook2).toHaveBeenCalledTimes(1);

    const hook3 = vi.fn();
    await provider.revoke("invalid", "access", { onRevoke: hook3 });
    expect(hook3).not.toHaveBeenCalled();
  });

  it("discovery document exposes endpoints and defaults", () => {
    const doc = provider.getDiscoveryDocument();
    expect(doc.issuer).toBe(issuer);
    expect(doc.authorization_endpoint).toBe(`${issuer}/authorize`);
    expect(doc.token_endpoint).toBe(`${issuer}/token`);
    expect(doc.introspection_endpoint).toBe(`${issuer}/introspect`);
    expect(doc.response_types_supported).toEqual(["code"]);
  });

  it("JWKS management and key rotation constraints", async () => {
    const [newOkp, otherOkp, acc1Okp] = await Promise.all([
      generateKey("Ed25519", { toJWK: { kid: "new" } }),
      generateKey("Ed25519", { toJWK: { kid: "other" } }),
      generateKey("Ed25519", { toJWK: { kid: "acc1" } }),
    ]);

    // Setting JWKS that doesn't include active signing key kid should fail
    expect(() => provider.setJwks([otherOkp.publicKey])).toThrow(
      /does not include the active signing key kid/,
    );

    // rotate without JWKS set should fail
    expect(() => provider.rotateAccessKey(newOkp.privateKey)).toThrow(
      /No JWKS set/,
    );

    // First set a JWKS including current and new kid so rotation can proceed
    provider.setJwks([acc1Okp.publicKey, newOkp.publicKey]);
    // Now rotate using existing JWKS
    provider.rotateAccessKey(newOkp.privateKey);
    expect(provider.accessKeyInfo.kid).toBe("new");

    // getPublicJwks returns what we set (public only)
    const pub = provider.getPublicJwks();
    expect(pub?.keys.find((k) => k.kid === "new")).toBeDefined();
    expect(provider.getPublicKeyByKid("new")).toBeDefined();
  });

  it("authorizeError helper returns shaped error", () => {
    const err = provider.authorizeError("invalid_request", "desc", "st");
    expect(err).toEqual({
      error: "invalid_request",
      error_description: "desc",
      state: "st",
    });
  });
});
