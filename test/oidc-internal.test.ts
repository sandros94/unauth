import { describe, it, expect } from "vitest";
import {
  buildOIDCDiscoveryDocument,
  computeTokenHash,
  verifyIdTokenHashes,
  buildUserInfo,
} from "../src/oidc/internal";

describe("oidc/internal", () => {
  it("builds discovery document with OIDC fields and defaults", () => {
    const doc = buildOIDCDiscoveryDocument({
      issuer: "https://issuer.example/",
    });
    expect(doc.issuer).toBe("https://issuer.example");
    expect(doc.authorization_endpoint).toBe("https://issuer.example/authorize");
    expect(doc.userinfo_endpoint).toBe("https://issuer.example/userinfo");
    expect(doc.scopes_supported).toContain("openid");
    expect(doc.subject_types_supported).toEqual(["public"]);
  });

  it("computes *_hash values per alg", async () => {
    const at = await computeTokenHash("a.b.c", "RS256");
    expect(typeof at).toBe("string");
    expect(at.length).toBeGreaterThan(10);
  });

  it("verifies at_hash and c_hash when provided", async () => {
    const access = "xyz.123";
    const code = "abc";
    const at_hash = await computeTokenHash(access, "RS256");
    const c_hash = await computeTokenHash(code, "RS256");
    await expect(
      verifyIdTokenHashes(
        {
          iss: "i",
          sub: "s",
          aud: "c",
          iat: 1,
          exp: 2,
          at_hash,
          c_hash,
        },
        "RS256",
        { access_token: access, code },
      ),
    ).resolves.toBeUndefined();
  });

  it("buildUserInfo picks and validates fields", () => {
    const profile = buildUserInfo({
      sub: "user1",
      name: "N",
      picture: "https://pics/1",
      email_verified: true,
      address: { country: "IT" },
      updated_at: 123,
      extra: "ok",
    });
    expect(profile.sub).toBe("user1");
    expect(profile.picture).toBe("https://pics/1");
    expect(profile.email_verified).toBe(true);
    expect(profile.address).toEqual({ country: "IT" });
    expect(profile.updated_at).toBe(123);
    // passthrough (via runtime shape)
    expect((profile as any).extra).toBe("ok");
  });
});
