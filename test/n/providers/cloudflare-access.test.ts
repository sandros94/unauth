import { describe, expect, expectTypeOf, it } from "vitest";

import {
  type ProfileContext,
  type OAuthProvider,
  buildAuthorizationUrl,
  isUnauthError,
  resolveProvider,
} from "../../../src/n/index.ts";
import {
  type CloudflareAccessProfile,
  defineCloudflareAccessHandler,
  defineCloudflareAccessProvider,
} from "../../../src/n/providers/cloudflare-access.ts";

const secret = { team: "acme", clientId: "client-1", clientSecret: "secret-1" };
const issuer = "https://acme.cloudflareaccess.com/cdn-cgi/access/sso/oidc/client-1";

const accessClaims = {
  iss: issuer,
  aud: "client-1",
  sub: "f1c2d3e4-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
  iat: 1790856000,
  exp: 1790859600,
  nonce: "n1",
  email: "ada@acme.example",
  email_verified: true,
  name: "Ada Lovelace",
  groups: ["engineering", "admins"],
};

const accessUserinfo = {
  sub: "f1c2d3e4-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
  email: "stale@acme.example",
  name: "Stale Name",
  picture: "https://cdn.acme.example/ada.png",
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
      return Response.json({
        issuer,
        authorization_endpoint: `${issuer}/authorization`,
        token_endpoint: `${issuer}/token`,
        userinfo_endpoint: `${issuer}/userinfo`,
        jwks_uri: `${issuer}/jwks`,
        scopes_supported: ["openid", "email", "profile", "groups"],
      });
    },
  });
  expect(seen).toEqual([`${issuer}/.well-known/openid-configuration`]);
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

describe("Cloudflare Access", () => {
  const provider = defineCloudflareAccessProvider(secret);

  it("is a discovered OpenID Connect provider on the team's SaaS app issuer", () => {
    expectTypeOf(provider).toEqualTypeOf<OAuthProvider<CloudflareAccessProfile>>();
    expect(provider).toMatchObject({
      id: "cloudflare-access",
      label: "Cloudflare Access",
      kind: "oidc",
      issuer,
      discovery: true,
      nonce: true,
      pkce: "S256",
      tokenAuth: "basic",
      scopes: ["openid", "email", "profile"],
    });
  });

  it("reflects the team and the client id in the issuer", () => {
    expect(
      defineCloudflareAccessProvider({ ...secret, team: "Contoso-1", clientId: "app/2" }).issuer,
    ).toBe("https://Contoso-1.cloudflareaccess.com/cdn-cgi/access/sso/oidc/app%2F2");
  });

  it("refuses a team that is not a DNS label", () => {
    for (const team of ["", "acme.cloudflareaccess.com", "-acme", "ac me", "a".repeat(64)]) {
      let error: unknown;
      try {
        defineCloudflareAccessProvider({ ...secret, team });
      } catch (caught) {
        error = caught;
      }
      expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    }
  });

  it("takes its endpoints from discovery under the issuer", async () => {
    expect(provider.authorization).toBeUndefined();
    expect(await discovered(provider)).toMatchObject({
      authorization: `${issuer}/authorization`,
      token: `${issuer}/token`,
      userinfo: `${issuer}/userinfo`,
      jwks: `${issuer}/jwks`,
    });
  });

  it("sends PKCE S256 and a nonce, with groups opt-in through scopes", async () => {
    expect(authorizationQuery(await discovered(provider))).toMatchObject({
      client_id: "client-1",
      scope: "openid email profile",
      code_challenge: "c",
      code_challenge_method: "S256",
      nonce: "n",
    });
    const scopes = ["openid", "email", "profile", "groups"];
    const custom = await discovered(defineCloudflareAccessProvider({ ...secret, scopes }));
    expect(authorizationQuery(custom).scope).toBe("openid email profile groups");
  });

  it("maps the id_token claims merged over userinfo, keeping the groups", async () => {
    const identity = await provider.profile(
      context({ claims: accessClaims, userinfo: accessUserinfo }),
    );

    expect(identity).toMatchObject({
      subject: "f1c2d3e4-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
      name: "Ada Lovelace",
      email: "ada@acme.example",
      emailVerified: true,
      avatar: "https://cdn.acme.example/ada.png",
    });
    expect(identity.profile.groups).toEqual(["engineering", "admins"]);
  });

  it("refuses claims without a subject or with malformed groups", async () => {
    const { sub: _sub, ...claims } = accessClaims;
    const missing = await rejection(
      provider.profile(context({ claims: claims as unknown as typeof accessClaims })),
    );
    expect(isUnauthError(missing, "ERR_AUTHN_PROFILE_INVALID")).toBe(true);

    const malformed = await rejection(
      provider.profile(context({ claims: { ...accessClaims, groups: "admins" } })),
    );
    expect(isUnauthError(malformed, "ERR_AUTHN_PROFILE_INVALID")).toBe(true);
  });

  it("refuses a sign-in without id_token claims", async () => {
    const error = await rejection(provider.profile(context({ userinfo: accessUserinfo })));
    expect(isUnauthError(error, "ERR_AUTHN_PROFILE_INVALID")).toBe(true);
  });

  it("exposes a handler preset", () => {
    expect(defineCloudflareAccessHandler).toBeTypeOf("function");
  });
});
