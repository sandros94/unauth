import { describe, expect, expectTypeOf, it } from "vitest";

import {
  type ProfileContext,
  type OAuthProvider,
  buildAuthorizationUrl,
  isUnauthError,
  resolveProvider,
} from "../../../src/n/index.ts";
import {
  type VercelProfile,
  defineVercelHandler,
  defineVercelProvider,
} from "../../../src/n/providers/vercel.ts";

const secret = { clientId: "client-1", clientSecret: "secret-1" };

const vercelDiscovery = {
  issuer: "https://vercel.com",
  authorization_endpoint: "https://vercel.com/oauth/authorize",
  token_endpoint: "https://api.vercel.com/login/oauth/token",
  userinfo_endpoint: "https://api.vercel.com/login/oauth/userinfo",
  jwks_uri: "https://vercel.com/.well-known/jwks",
  code_challenge_methods_supported: ["S256"],
  scopes_supported: ["openid", "email", "profile", "offline_access"],
};

const vercelClaims = {
  iss: "https://vercel.com",
  aud: "client-1",
  sub: "usr_2kN8x1Q4bVfA",
  iat: 1790856000,
  exp: 1790859600,
  nonce: "n1",
  email: "ada@example.com",
  email_verified: true,
  name: "Ada Lovelace",
  preferred_username: "ada",
  picture: "https://vercel.com/api/www/avatar/2kN8x1Q4bVfA",
};

const vercelUserinfo = {
  sub: "usr_2kN8x1Q4bVfA",
  email: "stale@example.com",
  email_verified: false,
  name: "Stale Name",
  preferred_username: "ada",
  picture: "https://vercel.com/api/www/avatar/stale",
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

async function discovered<T>(provider: OAuthProvider<T>): Promise<OAuthProvider<T>> {
  const seen: string[] = [];
  const resolved = await resolveProvider(provider, {
    fetch: async (input, init) => {
      seen.push(new Request(input, init).url);
      return Response.json(vercelDiscovery);
    },
  });
  expect(seen).toEqual(["https://vercel.com/.well-known/openid-configuration"]);
  return resolved;
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

describe("Vercel", () => {
  const provider = defineVercelProvider(secret);

  it("is a discovered OpenID Connect provider on https://vercel.com", () => {
    expectTypeOf(provider).toEqualTypeOf<OAuthProvider<VercelProfile>>();
    expect(provider).toMatchObject({
      id: "vercel",
      label: "Vercel",
      kind: "oidc",
      issuer: "https://vercel.com",
      discovery: true,
      nonce: true,
      pkce: "S256",
      scopes: ["openid", "email", "profile"],
    });
  });

  it("takes its endpoints from discovery", async () => {
    expect(provider.authorization).toBeUndefined();
    expect(await discovered(provider)).toMatchObject({
      authorization: "https://vercel.com/oauth/authorize",
      token: "https://api.vercel.com/login/oauth/token",
      userinfo: "https://api.vercel.com/login/oauth/userinfo",
      jwks: "https://vercel.com/.well-known/jwks",
    });
  });

  it("sends PKCE S256 and a nonce with the default scopes", async () => {
    expect(authorizationQuery(await discovered(provider))).toMatchObject({
      client_id: "client-1",
      scope: "openid email profile",
      code_challenge: "c",
      code_challenge_method: "S256",
      nonce: "n",
    });
  });

  it("replaces the scopes, keeping offline_access opt-in", async () => {
    const scopes = ["openid", "email", "offline_access"];
    const custom = await discovered(defineVercelProvider({ ...secret, scopes }));
    expect(authorizationQuery(custom).scope).toBe("openid email offline_access");
  });

  it("uses Basic auth for confidential clients and none for public ones", () => {
    expect(provider.tokenAuth).toBe("basic");
    expect(defineVercelProvider({ clientId: "public" }).tokenAuth).toBe("none");
  });

  it("maps the id_token claims merged over userinfo", async () => {
    const identity = await provider.profile(
      context({ claims: vercelClaims, userinfo: vercelUserinfo }),
    );

    expect(identity).toMatchObject({
      subject: "usr_2kN8x1Q4bVfA",
      name: "Ada Lovelace",
      email: "ada@example.com",
      emailVerified: true,
      avatar: "https://vercel.com/api/www/avatar/2kN8x1Q4bVfA",
    });
    expect(identity.profile.preferred_username).toBe("ada");
  });

  it("falls back to preferred_username without a name", async () => {
    const { name: _name, ...claims } = vercelClaims;
    const identity = await provider.profile(context({ claims }));
    expect(identity.name).toBe("ada");
  });

  it("refuses claims without a subject", async () => {
    const { sub: _sub, ...claims } = vercelClaims;
    const error = await rejection(
      provider.profile(context({ claims: claims as unknown as typeof vercelClaims })),
    );
    expect(isUnauthError(error, "ERR_AUTHN_PROFILE_INVALID")).toBe(true);
  });

  it("refuses a sign-in without id_token claims", async () => {
    const error = await rejection(provider.profile(context({ userinfo: vercelUserinfo })));
    expect(isUnauthError(error, "ERR_AUTHN_PROFILE_INVALID")).toBe(true);
  });

  it("exposes a handler preset", () => {
    expect(defineVercelHandler).toBeTypeOf("function");
  });
});
