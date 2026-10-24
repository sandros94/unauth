import { describe, expect, expectTypeOf, it } from "vitest";

import {
  type ProfileContext,
  type OAuthProvider,
  buildAuthorizationUrl,
  exchangeCode,
  isUnauthError,
} from "../../../src/n/index.ts";
import {
  type SpotifyProfile,
  defineSpotifyHandler,
  defineSpotifyProvider,
} from "../../../src/n/providers/spotify.ts";

const secret = { clientId: "client-1", clientSecret: "secret-1" };

const spotifyMe = {
  id: "wizzler",
  display_name: "JM Wizzler",
  email: "wizzler@example.com",
  images: [
    { url: "https://i.scdn.co/image/large.jpg", height: 300, width: 300 },
    { url: "https://i.scdn.co/image/small.jpg", height: 64, width: 64 },
  ],
  country: "SE",
  product: "premium",
  uri: "spotify:user:wizzler",
  href: "https://api.spotify.com/v1/users/wizzler",
  external_urls: { spotify: "https://open.spotify.com/user/wizzler" },
  followers: { href: null, total: 3829 },
  explicit_content: { filter_enabled: false, filter_locked: false },
  type: "user",
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

describe("Spotify", () => {
  it("is configured for Spotify's endpoints", () => {
    const provider = defineSpotifyProvider(secret);
    expectTypeOf(provider).toEqualTypeOf<OAuthProvider<SpotifyProfile>>();
    expect(provider).toMatchObject({
      id: "spotify",
      kind: "oauth2",
      authorization: "https://accounts.spotify.com/authorize",
      token: "https://accounts.spotify.com/api/token",
      userinfo: "https://api.spotify.com/v1/me",
      scopes: ["user-read-email", "user-read-private"],
      scopeSeparator: " ",
    });
  });

  it("uses Basic auth without PKCE for a confidential client", async () => {
    const provider = defineSpotifyProvider(secret);
    expect(provider).toMatchObject({ tokenAuth: "basic", pkce: false });
    const query = authorizationQuery(provider);
    expect(query).toMatchObject({
      client_id: "client-1",
      scope: "user-read-email user-read-private",
    });
    expect(query).not.toHaveProperty("code_challenge");

    let authorization: string | null = null;
    let body = "";
    await exchangeCode(provider, {
      code: "c",
      redirectUri: "https://app.test/cb",
      fetch: async (_url, init) => {
        authorization = new Headers(init?.headers).get("authorization");
        body = init?.body instanceof URLSearchParams ? init.body.toString() : "";
        return Response.json({ access_token: "at", token_type: "Bearer" });
      },
    });
    expect(authorization).toBe(`Basic ${btoa("client-1:secret-1")}`);
    expect(new URLSearchParams(body).has("client_secret")).toBe(false);
  });

  it("uses PKCE S256 without client authentication for a public client", () => {
    const provider = defineSpotifyProvider({ clientId: "public" });
    expect(provider).toMatchObject({ tokenAuth: "none", pkce: "S256" });
    expect(authorizationQuery(provider)).toMatchObject({
      client_id: "public",
      code_challenge: "c",
      code_challenge_method: "S256",
    });
  });

  it("maps the user with its first image, without vouching for the email", async () => {
    const identity = await defineSpotifyProvider(secret).profile(context({ userinfo: spotifyMe }));
    expect(identity).toEqual({
      subject: "wizzler",
      profile: spotifyMe,
      name: "JM Wizzler",
      avatar: "https://i.scdn.co/image/large.jpg",
      email: "wizzler@example.com",
    });
    expect(identity.emailVerified).toBeUndefined();
  });

  it("leaves a null display name and an empty image list unset", async () => {
    const identity = await defineSpotifyProvider(secret).profile(
      context({ userinfo: { ...spotifyMe, display_name: null, images: [], email: undefined } }),
    );
    expect(identity).toEqual({ subject: "wizzler", profile: identity.profile });
  });

  it("refuses a payload without a string id", async () => {
    const error = await rejection(
      defineSpotifyProvider(secret).profile(context({ userinfo: { display_name: "x" } })),
    );
    expect(isUnauthError(error, "ERR_AUTHN_PROFILE_INVALID")).toBe(true);
  });

  it("exposes a handler preset", () => {
    expect(defineSpotifyHandler).toBeTypeOf("function");
  });
});
