import { describe, expect, expectTypeOf, it } from "vitest";

import {
  type ProfileContext,
  type OAuthProvider,
  buildAuthorizationUrl,
  exchangeCode,
  isUnauthError,
} from "../../../src/n/index.ts";
import {
  type NetlifyProfile,
  defineNetlifyHandler,
  defineNetlifyProvider,
} from "../../../src/n/providers/netlify.ts";

const secret = { clientId: "client-1", clientSecret: "secret-1" };

const netlifyUser = {
  id: "5f1c2d3e4a5b6c7d8e9f0a1b",
  uid: "5f1c2d3e4a5b6c7d8e9f0a1b",
  full_name: "Ada Lovelace",
  avatar_url: "https://www.gravatar.com/avatar/00000000000000000000000000000000?d=404",
  email: "ada@example.com",
  affiliate_id: "",
  site_count: 3,
  created_at: "2020-07-25T10:00:00.000Z",
  last_login: "2026-10-20T08:30:00.000Z",
  login_providers: ["github"],
};

function context(overrides: Partial<ProfileContext> = {}): ProfileContext {
  return {
    tokens: { access_token: "at-1", token_type: "Bearer", raw: {} },
    params: {},
    fetch: async () => {
      throw new Error("no network in profile tests");
    },
    ...overrides,
  };
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => {
      throw new Error("expected a rejection");
    },
    (error: unknown) => error,
  );
}

function authorizationQuery(provider: OAuthProvider<unknown>): Record<string, string> {
  const url = buildAuthorizationUrl(provider, {
    redirectUri: "https://app.test/cb",
    state: "s",
    nonce: provider.nonce ? "n" : undefined,
    pkce: provider.pkce ? { challenge: "c", method: "S256" } : undefined,
  });
  return Object.fromEntries(url.searchParams);
}

describe("Netlify", () => {
  const provider = defineNetlifyProvider(secret);

  it("is configured for Netlify's endpoints without scopes or PKCE", () => {
    expectTypeOf(provider).toEqualTypeOf<OAuthProvider<NetlifyProfile>>();
    expect(provider).toMatchObject({
      id: "netlify",
      kind: "oauth2",
      authorization: "https://app.netlify.com/authorize",
      token: "https://api.netlify.com/oauth/token",
      userinfo: "https://api.netlify.com/api/v1/user",
      tokenAuth: "body",
      pkce: false,
      scopes: [],
    });
    const query = authorizationQuery(provider);
    expect(query).toMatchObject({ client_id: "client-1", response_type: "code" });
    expect(query).not.toHaveProperty("scope");
    expect(query).not.toHaveProperty("code_challenge");
  });

  it("sends the client credentials in the token request body", async () => {
    let body = "";
    await exchangeCode(provider, {
      code: "c",
      redirectUri: "https://app.test/cb",
      fetch: async (_url, init) => {
        body = init?.body instanceof URLSearchParams ? init.body.toString() : "";
        return Response.json({ access_token: "at", token_type: "Bearer" });
      },
    });
    const form = new URLSearchParams(body);
    expect(form.get("client_id")).toBe("client-1");
    expect(form.get("client_secret")).toBe("secret-1");
  });

  it("maps the user without vouching for the email", async () => {
    const identity = await provider.profile(context({ userinfo: netlifyUser }));
    expect(identity).toEqual({
      subject: "5f1c2d3e4a5b6c7d8e9f0a1b",
      profile: netlifyUser,
      name: "Ada Lovelace",
      avatar: netlifyUser.avatar_url,
      email: "ada@example.com",
    });
    expect(identity.emailVerified).toBeUndefined();
  });

  it("leaves null members unset", async () => {
    const identity = await provider.profile(
      context({ userinfo: { ...netlifyUser, full_name: null, avatar_url: null, email: null } }),
    );
    expect(identity).toEqual({ subject: netlifyUser.id, profile: identity.profile });
  });

  it("refuses a payload without a string id", async () => {
    const error = await rejection(provider.profile(context({ userinfo: { uid: "x" } })));
    expect(isUnauthError(error, "ERR_AUTHN_PROFILE_INVALID")).toBe(true);
  });

  it("exposes a handler preset", () => {
    expect(defineNetlifyHandler).toBeTypeOf("function");
  });
});
