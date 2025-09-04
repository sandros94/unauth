import { describe, it, expect } from "vitest";
import { generateKey } from "unjwt/jwk";
import { type JWTClaims, verify } from "unjwt/jws";

import { OIDCProvider } from "../src/oidc/service";

describe("OIDCProvider", async () => {
  const issuer = "https://op.example";
  const [atKey, idKey] = await Promise.all([
    generateKey("HS256", { toJWK: { kid: "acc1" } }),
    generateKey("HS256", { toJWK: { kid: "id1" } }),
  ]);
  const rtSecret = "refresh-secret";

  const op = new OIDCProvider({
    issuer,
    accessToken: { privateKey: atKey, signOptions: { alg: "HS256" } },
    refreshToken: { privateKey: rtSecret },
    idToken: { privateKey: idKey, signOptions: { alg: "HS256" } },
    defaultScope: "openid profile",
    availableScopes: ["openid", "profile", "email"],
  });

  it("validate authorize requires openid and only code/query", async () => {
    await expect(
      op.authorize(
        {
          response_type: "code",
          client_id: "c",
          redirect_uri: "https://cb",
          scope: "profile", // missing openid
          code_challenge: "v",
        },
        async () => ({ sub: "u" }),
      ),
    ).rejects.toThrow(/Missing required openid/);

    // valid
    const ok = await op.authorize(
      {
        response_type: "code",
        client_id: "c",
        redirect_uri: "https://cb",
        scope: "openid profile",
        code_challenge: "v",
      },
      async () => ({ sub: "u" }),
    );
    expect(ok.code).toBeTypeOf("string");
  });

  it("builds and introspects ID Token", async () => {
    const id = await op.buildIdToken({
      subject: "u1",
      audience: "c1",
      nonce: "n",
      access_token: "at",
    });
    const { payload } = await verify<JWTClaims>(id, idKey);
    expect(payload.iss).toBe(issuer);
    expect(payload.sub).toBe("u1");
    expect(payload.aud).toBe("c1");
    expect(payload.nonce).toBe("n");
    expect(typeof payload.exp).toBe("number");
    expect(typeof payload.iat).toBe("number");

    const res = await op.introspectIdToken(id);
    expect(res.active).toBe(true);
    expect(res.claims?.iss).toBe(issuer);

    const bad = await op.introspectIdToken("x.y.z");
    expect(bad.active).toBe(false);
  });

  it("discovery document merges OAuth and OIDC bits", () => {
    const d = op.getDiscoveryDocument();
    expect(d.issuer).toBe(issuer);
    expect(d.authorization_endpoint).toBe(`${issuer}/authorize`);
    expect(d.userinfo_endpoint).toBe(`${issuer}/userinfo`);
    expect(d.scopes_supported).toContain("openid");
    expect(d.response_types_supported).toContain("code");
  });

  it("JWKS management across OAuth and OIDC and ID signing key rotation", async () => {
    const [newOkp, otherOkp, id1Okp] = await Promise.all([
      generateKey("Ed25519", { toJWK: { kid: "new" } }),
      generateKey("Ed25519", { toJWK: { kid: "other" } }),
      generateKey("Ed25519", { toJWK: { kid: "id1" } }),
    ]);

    // Setting JWKS that doesn't include ID key should fail
    expect(() => op.setJwks([otherOkp.publicKey])).toThrow(
      /does not include the active signing key kid/,
    );

    // rotate without JWKS set should fail
    expect(() => op.rotateIDKey(newOkp.privateKey)).toThrow(/No JWKS set/);

    // First set JWKS including both current and new kids
    op.setJwks([id1Okp.publicKey, newOkp.publicKey]);
    // rotate using current JWKS
    op.rotateIDKey(newOkp.privateKey);
    expect(op.idTokenKeyInfo.kid).toBe("new");

    // getPublicJwks returns merged keys (currently only one)
    const pub = op.getPublicJwks();
    expect(pub?.keys.find((k) => k.kid === "new")).toBeDefined();
    expect(op.getPublicKeyByKid("new")).toBeDefined();
  });
});
