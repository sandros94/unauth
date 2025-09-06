import { describe, it, expect } from "vitest";
import { hash } from "unsecure";
import { verify } from "unjwt/jws";

import {
  buildIdToken,
  buildOIDCDiscoveryDocument,
  buildUserInfo,
  computeTokenHash,
  validateOIDCAuthorizeRequest,
  verifyIdTokenHashes,
} from "../src/oidc/internal";

import type { JWK } from "unjwt";

function hs256Key(secret: string): JWK {
  const k = Buffer.from(secret)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  return { kty: "oct", k, alg: "HS256" };
}

describe("oidc/id-token > computeTokenHash", () => {
  it("computes left-half b64url SHA-256 for RS256", async () => {
    const value = "abc";
    const expectedFull = await hash(value, {
      algorithm: "SHA-256",
      returnAs: "b64url",
    });
    const fullB64 = expectedFull.replace(/-/g, "+").replace(/_/g, "/");
    const fullBuf = Buffer.from(fullB64, "base64");
    const halfBuf = fullBuf.subarray(0, Math.floor(fullBuf.length / 2));
    const expectedHalf = halfBuf
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");

    const actual = await computeTokenHash(value, "RS256");
    expect(actual).toBe(expectedHalf);
  });

  it("rejects unsupported alg", async () => {
    await expect(computeTokenHash("x", "none")).rejects.toThrow();
  });
});

describe("oidc/id-token > build & verify", () => {
  const key = hs256Key("testsecret");
  const issuer = "https://issuer.example";

  it("builds an ID Token (code flow) with at_hash/c_hash when provided", async () => {
    const args: any = {
      subject: "user-123",
      audience: "client-abc",
      nonce: "n-0",
      auth_time: 1_700_000_000,
      acr: "urn:mace:incommon:iap:silver",
      amr: ["pwd"] as string[],
      azp: "client-abc",
      access_token: "at-value",
      code: "code-value",
    };

    const token = await buildIdToken(args, {
      issuer,
      jwsKey: key,
    });

    const { payload } = await verify<any>(token, key);
    expect(payload.iss).toBe(issuer);
    expect(payload.sub).toBe(args.subject);
    expect(payload.aud).toBe(args.audience);
    expect(payload.nonce).toBe(args.nonce);
    expect(payload.acr).toBe(args.acr);
    expect(payload.amr).toEqual(args.amr);
    expect(payload.azp).toBe(args.azp);
    expect(typeof payload.exp).toBe("number");
    expect(typeof payload.iat).toBe("number");
    expect(payload.at_hash).toBeDefined();
    expect(payload.c_hash).toBeDefined();

    await verifyIdTokenHashes(payload, "HS256", {
      access_token: args.access_token,
      code: args.code,
    });
  });

  it("applies default ID Token lifetime when expiresIn omitted", async () => {
    const token = await buildIdToken(
      { subject: "u1", audience: "c1" },
      { issuer, jwsKey: key, signOptions: { alg: "HS256" } },
    );
    const { payload } = await verify<{ exp: number; iat: number }>(token, key);
    expect(payload.exp - payload.iat).toBeGreaterThanOrEqual(3600);
  });
});

describe("oidc/discovery", () => {
  it("builds a discovery document with defaults", () => {
    const doc = buildOIDCDiscoveryDocument({
      issuer: "https://i",
      authorization_endpoint: "https://i/auth",
      token_endpoint: "https://i/token",
      userinfo_endpoint: "https://i/userinfo",
      jwks_uri: "https://i/jwks",
    });
    expect(doc.issuer).toBe("https://i");
    expect(doc.authorization_endpoint).toContain("/auth");
    expect(doc.response_types_supported).toContain("code");
  });
});

describe("oidc/authorize validation (OAuth 2.1)", () => {
  it("requires openid scope", () => {
    expect(() =>
      validateOIDCAuthorizeRequest({
        response_type: "code",
        client_id: "c",
        redirect_uri: "https://cb",
        scope: "profile email",
      }),
    ).toThrow();
  });

  it("rejects non-code response_type and non-query response_mode", () => {
    expect(() =>
      validateOIDCAuthorizeRequest({
        response_type: "id_token",
        client_id: "c",
        redirect_uri: "https://cb",
        scope: "openid",
      } as any),
    ).toThrow();

    expect(() =>
      validateOIDCAuthorizeRequest({
        response_type: "code",
        client_id: "c",
        redirect_uri: "https://cb",
        scope: "openid",
        response_mode: "form_post",
      }),
    ).toThrow();
  });

  it("accepts code + query with openid", () => {
    expect(() =>
      validateOIDCAuthorizeRequest({
        response_type: "code",
        client_id: "c",
        redirect_uri: "https://cb",
        scope: "openid profile",
        response_mode: "query",
      }),
    ).not.toThrow();
  });
});

describe("oidc/userinfo", () => {
  it("filters and returns standard claims", () => {
    const out = buildUserInfo({
      sub: "u1",
      email: "u1@example.com",
      email_verified: false,
      phone_number_verified: true,
      unknown: "x",
      __proto__: { polluted: true },
    });
    expect(out.sub).toBe("u1");
    expect(out.email).toBe("u1@example.com");
    expect(out).toHaveProperty("email_verified", false);
    expect(out).toHaveProperty("phone_number_verified", true);
    // non-standard claim is preserved on the object itself
    expect(out.unknown).toBe("x");
    // prototype should not be polluted
    expect(out.polluted).toBeUndefined();
  });
});
