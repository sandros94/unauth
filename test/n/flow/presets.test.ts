import { describe, expect, expectTypeOf, it } from "vitest";

import {
  type OidcProfile,
  type OAuthProvider,
  defineOAuth2Provider,
  defineOidcProvider,
} from "../../../src/n/index.ts";

describe("oauth2 / oidc typing", () => {
  it("pins the profile type when no mapper is given", () => {
    const plain = defineOAuth2Provider({
      id: "p",
      clientId: "c",
      authorization: "https://idp.test/a",
      token: "https://idp.test/t",
      userinfo: "https://idp.test/u",
    });
    const generic = defineOidcProvider({ issuer: "https://idp.test", clientId: "c" });

    expectTypeOf(plain).toEqualTypeOf<OAuthProvider>();
    expectTypeOf(generic).toEqualTypeOf<OAuthProvider<OidcProfile>>();
  });

  it("takes the profile type from a mapper", () => {
    interface Custom {
      login: string;
    }
    const custom = defineOAuth2Provider({
      id: "p",
      clientId: "c",
      authorization: "https://idp.test/a",
      token: "https://idp.test/t",
      profile: () => ({ subject: "1", profile: { login: "x" } }),
    });

    expectTypeOf(custom).toEqualTypeOf<OAuthProvider<Custom>>();
    expect(custom.id).toBe("p");
  });

  it("maps OIDC claims merged with userinfo into OidcProfile", async () => {
    const provider = defineOidcProvider({ issuer: "https://idp.test", clientId: "c" });
    const identity = await provider.profile({
      tokens: { access_token: "a", token_type: "Bearer", raw: {} },
      claims: { iss: "https://idp.test", sub: "u1", aud: "c", exp: 2, iat: 1, email: "a@b.c" },
      userinfo: { sub: "u1", name: "Ada", email_verified: "true" },
      params: {},
      fetch,
    });

    expect(identity).toMatchObject({
      subject: "u1",
      name: "Ada",
      email: "a@b.c",
      emailVerified: true,
    });
    expect(identity.profile.sub).toBe("u1");
  });
});
