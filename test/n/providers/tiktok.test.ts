import { describe, expect, expectTypeOf, it } from "vitest";

import {
  type ProfileContext,
  type OAuthProvider,
  buildAuthorizationUrl,
  exchangeCode,
  isUnauthError,
} from "../../../src/n/index.ts";
import {
  type TikTokProfile,
  defineTikTokHandler,
  defineTikTokProvider,
} from "../../../src/n/providers/tiktok.ts";

const secret = { clientId: "key-1", clientSecret: "secret-1" };

const tiktokUser = {
  open_id: "723f24d7-e717-40f8-a2b6-cb8464cd23b4",
  union_id: "c9c60f44-a68e-4f5d-84dd-ce22faeb0ba1",
  avatar_url: "https://p16-sign.tiktokcdn-us.com/avatar.jpeg",
  avatar_url_100: "https://p16-sign.tiktokcdn-us.com/avatar-100.jpeg",
  avatar_large_url: "https://p16-sign.tiktokcdn-us.com/avatar-large.jpeg",
  display_name: "Ada Lovelace",
};

const tiktokUserInfo = {
  data: { user: tiktokUser },
  error: { code: "ok", message: "", log_id: "20261024083000010000000000000000" },
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

describe("TikTok", () => {
  const provider = defineTikTokProvider(secret);

  it("is configured for Login Kit for Web", () => {
    expectTypeOf(provider).toEqualTypeOf<OAuthProvider<TikTokProfile>>();
    expect(provider).toMatchObject({
      id: "tiktok",
      kind: "oauth2",
      authorization: "https://www.tiktok.com/v2/auth/authorize/",
      token: "https://open.tiktokapis.com/v2/oauth/token/",
      clientIdParameter: "client_key",
      tokenAuth: "body",
      pkce: false,
      scopes: ["user.info.basic"],
      scopeSeparator: ",",
    });
    expect(provider.userinfo).toBe(
      "https://open.tiktokapis.com/v2/user/info/?fields=open_id,union_id,avatar_url,avatar_url_100,avatar_large_url,display_name",
    );
  });

  it("names the client as client_key in the authorization request", () => {
    const query = authorizationQuery(
      defineTikTokProvider({ ...secret, scopes: ["user.info.basic", "user.info.profile"] }),
    );
    expect(query).toMatchObject({
      client_key: "key-1",
      response_type: "code",
      scope: "user.info.basic,user.info.profile",
    });
    expect(query).not.toHaveProperty("client_id");
    expect(query).not.toHaveProperty("code_challenge");
  });

  it("names the client as client_key in the token request body", async () => {
    let body = "";
    await exchangeCode(provider, {
      code: "c",
      redirectUri: "https://app.test/cb",
      fetch: async (_url, init) => {
        body = init?.body instanceof URLSearchParams ? init.body.toString() : "";
        return Response.json({ access_token: "at", token_type: "Bearer", open_id: "o" });
      },
    });
    const form = new URLSearchParams(body);
    expect(form.get("client_key")).toBe("key-1");
    expect(form.get("client_secret")).toBe("secret-1");
    expect(form.has("client_id")).toBe(false);
  });

  it("unwraps data.user, without any email", async () => {
    const identity = await provider.profile(context({ userinfo: tiktokUserInfo }));
    expect(identity).toEqual({
      subject: tiktokUser.open_id,
      profile: tiktokUser,
      name: "Ada Lovelace",
      avatar: tiktokUser.avatar_url,
    });
    expect(identity.email).toBeUndefined();
  });

  it("refuses an answer whose error code is not ok", async () => {
    const error = await rejection(
      provider.profile(
        context({
          userinfo: {
            data: {},
            error: { code: "access_token_invalid", message: "invalid", log_id: "1" },
          },
        }),
      ),
    );
    expect(isUnauthError(error, "ERR_AUTHN_PROFILE_INVALID")).toBe(true);
    expect(String(error)).toContain("access_token_invalid");
  });

  it("refuses a payload without an open_id", async () => {
    const error = await rejection(
      provider.profile(context({ userinfo: { data: { user: { display_name: "x" } } } })),
    );
    expect(isUnauthError(error, "ERR_AUTHN_PROFILE_INVALID")).toBe(true);
  });

  it("exposes a handler preset", () => {
    expect(defineTikTokHandler).toBeTypeOf("function");
  });
});
