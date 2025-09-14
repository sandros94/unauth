import { beforeAll, describe, expect, it } from "vitest";
import type { JWK } from "unjwt";

import type { TokenResponse } from "../src";
import { OIDCProvider } from "../src/oidc";
import { generateJwk } from "../src/utils";

describe("OIDCProvider", () => {
  const now = new Date("2025-01-01T00:00:00Z");

  let atPriv!: JWK;
  let atPub!: JWK;
  let idPriv!: JWK;
  let idPub!: JWK;

  beforeAll(async () => {
    const at = await generateJwk("ES256", { params: { kid: "at-1" } });
    atPriv = at.privateKey;
    atPub = at.publicKey;
    const id = await generateJwk("ES256", { params: { kid: "id-1" } });
    idPriv = id.privateKey;
    idPub = id.publicKey;
  });

  it("issues id_token when scope contains openid", async () => {
    const state: { code?: string } = {};
    const provider = new OIDCProvider({
      issuer: "https://issuer.oidc2",
      authorizationCode: { privateKey: "ac" },
      refreshToken: { privateKey: "rt" },
      accessToken: { privateKey: atPriv },
      idToken: { privateKey: idPriv },
      hooks: {
        onAuthorizeRequest: () => ({
          response_type: "code",
          client_id: "c1",
          code_challenge: "ver",
          redirect_uri: "https://app/cb",
          scope: "openid profile",
          claims: { sub: "user1" },
        }),
        onTokenRequest: () => ({
          grant_type: "authorization_code",
          code: state.code!,
          client_id: "c1",
          code_verifier: "ver",
        }),
      },
      jwks: [atPub, idPub],
      currentDate: now,
    });

    const redirect = await provider.issueAuthorizationCode();
    const url = new URL(redirect as string);
    state.code = url.searchParams.get("code") || undefined;
    expect(state.code).toBeTruthy();

    const tokenRes = await provider.issueAccessToken();
    expect(tokenRes).toHaveProperty("access_token");
    expect(tokenRes).toHaveProperty("id_token");

    const idt = await provider.introspectIdToken(
      (tokenRes as TokenResponse & { id_token: string }).id_token,
    );
    expect(idt.active).toBe(true);
    expect(idt.claims?.sub).toBe("user1");
  });
});
