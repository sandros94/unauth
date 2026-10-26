import { describe, expect, expectTypeOf, it } from "vitest";
import { generateJWK, verify } from "unjwt";

import {
  type IdTokenClaims,
  type ProfileContext,
  type OAuthProvider,
  buildAuthorizationUrl,
  isUnauthError,
} from "../../../src/n/index.ts";
import {
  type AppleProfile,
  appleClientSecret,
  defineAppleProvider,
} from "../../../src/n/providers/apple.ts";
import {
  type DiscordProfile,
  discordAvatar,
  defineDiscordProvider,
} from "../../../src/n/providers/discord.ts";
import { type FacebookProfile, defineFacebookProvider } from "../../../src/n/providers/facebook.ts";
import { type GitHubProfile, defineGitHubProvider } from "../../../src/n/providers/github.ts";
import { type GitLabProfile, defineGitLabProvider } from "../../../src/n/providers/gitlab.ts";
import { type GoogleProfile, defineGoogleProvider } from "../../../src/n/providers/google.ts";
import { type LinkedInProfile, defineLinkedInProvider } from "../../../src/n/providers/linkedin.ts";
import {
  type MicrosoftProfile,
  defineMicrosoftProvider,
} from "../../../src/n/providers/microsoft.ts";
import { type TwitchProfile, defineTwitchProvider } from "../../../src/n/providers/twitch.ts";
import { type XProfile, defineXProvider } from "../../../src/n/providers/x.ts";
import * as fixtures from "./_fixtures.ts";

const secret = { clientId: "client-1", clientSecret: "secret-1" };

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

describe("GitHub", () => {
  const provider = defineGitHubProvider(secret);

  it("is configured for GitHub's endpoints", () => {
    expectTypeOf(provider).toEqualTypeOf<OAuthProvider<GitHubProfile>>();
    expect(provider).toMatchObject({
      id: "github",
      kind: "oauth2",
      token: "https://github.com/login/oauth/access_token",
      userinfo: "https://api.github.com/user",
      tokenAuth: "body",
      pkce: "S256",
      scopes: ["read:user", "user:email"],
    });
    expect(provider.userinfoHeaders["user-agent"]).toBeTruthy();
  });

  it("takes the primary email from /user/emails when user:email was granted", async () => {
    const seen: Request[] = [];
    const identity = await provider.profile(
      context({
        tokens: {
          access_token: "at-1",
          token_type: "bearer",
          scope: "read:user,user:email",
          raw: {},
        },
        userinfo: fixtures.githubUser,
        fetch: async (input, init) => {
          seen.push(new Request(input, init));
          return Response.json(fixtures.githubEmails);
        },
      }),
    );

    expect(identity).toEqual({
      subject: "583231",
      profile: fixtures.githubUser,
      name: "The Octocat",
      avatar: "https://avatars.githubusercontent.com/u/583231?v=4",
      email: "octocat@github.com",
      emailVerified: true,
    });
    expect(seen[0]!.url).toBe("https://api.github.com/user/emails");
    expect(seen[0]!.headers.get("authorization")).toBe("Bearer at-1");
    expect(seen[0]!.headers.get("user-agent")).toBeTruthy();
  });

  it("falls back to the public email, unverified, without user:email", async () => {
    const identity = await provider.profile(
      context({
        tokens: { access_token: "at-1", token_type: "bearer", scope: "read:user", raw: {} },
        userinfo: { ...fixtures.githubUser, email: "public@example.com", name: null },
      }),
    );

    expect(identity).toMatchObject({ email: "public@example.com", name: "octocat" });
    expect(identity.emailVerified).toBeUndefined();
  });

  it("refuses a payload without a numeric id", async () => {
    const error = await rejection(provider.profile(context({ userinfo: { login: "x" } })));
    expect(isUnauthError(error, "ERR_AUTHN_PROFILE_INVALID")).toBe(true);
  });
});

describe("Google", () => {
  const provider = defineGoogleProvider(secret);

  it("is a discovered OpenID Connect provider", () => {
    expectTypeOf(provider).toEqualTypeOf<OAuthProvider<GoogleProfile>>();
    expect(provider).toMatchObject({
      id: "google",
      kind: "oidc",
      issuer: "https://accounts.google.com",
      discovery: true,
      nonce: true,
      pkce: "S256",
      scopes: ["openid", "email", "profile"],
    });
  });

  it("maps the id_token claims", async () => {
    const identity = await provider.profile(context({ claims: fixtures.googleClaims }));

    expect(identity).toMatchObject({
      subject: "110169484474386276334",
      name: "Ada Lovelace",
      email: "ada@example.com",
      emailVerified: true,
      avatar: "https://lh3.googleusercontent.com/a/photo.jpg",
    });
    expect(identity.profile.hd).toBe("example.com");
  });
});

describe("Discord", () => {
  const provider = defineDiscordProvider(secret);

  it("keeps PKCE on for the providers that support it", () => {
    for (const preset of [
      defineGitHubProvider(secret),
      defineGoogleProvider(secret),
      defineMicrosoftProvider(secret),
      defineDiscordProvider(secret),
      defineGitLabProvider(secret),
      defineXProvider(secret),
      defineFacebookProvider(secret),
    ]) {
      expect([preset.id, preset.pkce]).toEqual([preset.id, "S256"]);
    }
  });

  it("is configured for Discord's endpoints", () => {
    expectTypeOf(provider).toEqualTypeOf<OAuthProvider<DiscordProfile>>();
    expect(authorizationQuery(provider)).toMatchObject({
      scope: "identify email",
      code_challenge_method: "S256",
    });
    expect(provider.userinfo).toBe("https://discord.com/api/users/@me");
  });

  it("maps the user with its CDN avatar", async () => {
    const identity = await provider.profile(context({ userinfo: fixtures.discordUser }));

    expect(identity).toEqual({
      subject: "80351110224678912",
      profile: fixtures.discordUser,
      name: "Nelly",
      email: "nelly@discord.com",
      emailVerified: true,
      avatar:
        "https://cdn.discordapp.com/avatars/80351110224678912/8342729096ea3675442027381ff50dfe.png",
    });
  });

  it("builds animated and default avatars", () => {
    const id = "80351110224678912";
    expect(discordAvatar({ id, avatar: "a_123", discriminator: "0" })).toMatch(/\/a_123\.gif$/);
    expect(discordAvatar({ id, avatar: null, discriminator: "0" })).toBe(
      `https://cdn.discordapp.com/embed/avatars/${Number((BigInt(id) >> 22n) % 6n)}.png`,
    );
    expect(discordAvatar({ id, avatar: null, discriminator: "1337" })).toBe(
      "https://cdn.discordapp.com/embed/avatars/2.png",
    );
  });
});

describe("Microsoft", () => {
  it("defaults to the common tenant and reads Microsoft Graph", () => {
    const provider = defineMicrosoftProvider(secret);
    expectTypeOf(provider).toEqualTypeOf<OAuthProvider<MicrosoftProfile>>();
    expect(provider).toMatchObject({
      id: "microsoft",
      kind: "oauth2",
      authorization: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
      token: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
      userinfo: "https://graph.microsoft.com/v1.0/me",
      scopes: ["User.Read"],
    });
    expect(defineMicrosoftProvider({ ...secret, tenant: "contoso.onmicrosoft.com" }).token).toBe(
      "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token",
    );
  });

  it("maps the Graph user without vouching for mail", async () => {
    const identity = await defineMicrosoftProvider(secret).profile(
      context({ userinfo: fixtures.microsoftUser }),
    );

    expect(identity).toMatchObject({
      subject: "48d31887-5fad-4d73-a9f5-3c356e68a038",
      name: "Megan Bowen",
      email: "MeganB@contoso.com",
    });
    expect(identity.emailVerified).toBeUndefined();
  });
});

describe("Apple", () => {
  it("is OpenID Connect over form_post, without PKCE", async () => {
    const keys = await generateJWK("ES256");
    const provider = defineAppleProvider({
      clientId: "com.example.web",
      teamId: "TEAM",
      keyId: "KEY",
      privateKey: keys.privateKey,
    });
    expectTypeOf(provider).toEqualTypeOf<OAuthProvider<AppleProfile>>();
    expect(provider).toMatchObject({
      kind: "oidc",
      issuer: "https://appleid.apple.com",
      jwks: "https://appleid.apple.com/auth/keys",
      responseMode: "form_post",
      pkce: false,
      nonce: true,
      scopes: ["name", "email"],
    });
    const query = authorizationQuery(provider);
    expect(query).toMatchObject({ response_mode: "form_post", nonce: "n", scope: "name email" });
    expect(query).not.toHaveProperty("code_challenge");
  });

  it("mints a short-lived ES256 client secret from a JWK or a PEM", async () => {
    const keys = await generateJWK("ES256", { kid: "ignored" });
    const options = {
      clientId: "com.example.web",
      teamId: "TEAM",
      keyId: "KEY",
      privateKey: keys.privateKey,
    };

    const token = await appleClientSecret(options)();
    const { payload, protectedHeader } = await verify(token, keys.publicKey, {
      issuer: "TEAM",
      subject: "com.example.web",
      audience: "https://appleid.apple.com",
      requiredClaims: ["iat", "exp"],
    });

    expect(protectedHeader).toMatchObject({ alg: "ES256", kid: "KEY" });
    expect(payload.exp! - payload.iat!).toBeLessThanOrEqual(300);
  });

  it("does not keep a failed key import: the next secret imports again", async () => {
    const keys = await generateJWK("ES256");
    const options = {
      clientId: "com.example.web",
      teamId: "TEAM",
      keyId: "KEY",
      privateKey: "-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----" as
        | string
        | typeof keys.privateKey,
    };
    const mint = appleClientSecret(options);

    await expect(mint()).rejects.toBeInstanceOf(Error);
    await expect(mint()).rejects.toBeInstanceOf(Error);
    options.privateKey = keys.privateKey;
    const token = await mint();
    await verify(token, keys.publicKey, { issuer: "TEAM", audience: "https://appleid.apple.com" });
  });

  it("takes the name from the first-login user field and the email from the id_token", async () => {
    const keys = await generateJWK("ES256");
    const provider = defineAppleProvider({
      clientId: "com.example.web",
      teamId: "T",
      keyId: "K",
      privateKey: keys.privateKey,
    });

    const identity = await provider.profile(
      context({
        claims: fixtures.appleClaims as unknown as IdTokenClaims,
        params: { user: fixtures.appleFirstLoginUser.replace("x7k2@", "forged@") },
      }),
    );

    expect(identity).toMatchObject({
      subject: fixtures.appleClaims.sub,
      name: "Ada Lovelace",
      email: "x7k2@privaterelay.appleid.com",
      emailVerified: true,
    });
    expect(identity.profile.user?.name).toEqual({ firstName: "Ada", lastName: "Lovelace" });
  });

  it("ignores a user field that is not JSON", async () => {
    const keys = await generateJWK("ES256");
    const provider = defineAppleProvider({
      clientId: "c",
      teamId: "T",
      keyId: "K",
      privateKey: keys.privateKey,
    });

    const identity = await provider.profile(
      context({
        claims: fixtures.appleClaims as unknown as IdTokenClaims,
        params: { user: "{oops" },
      }),
    );

    expect(identity.name).toBeUndefined();
    expect(identity.profile.user).toBeUndefined();
  });
});

describe("GitLab", () => {
  it("serves GitLab.com or a self-managed base URL", () => {
    expectTypeOf(defineGitLabProvider(secret)).toEqualTypeOf<OAuthProvider<GitLabProfile>>();
    expect(defineGitLabProvider(secret).userinfo).toBe("https://gitlab.com/api/v4/user");
    expect(defineGitLabProvider({ ...secret, baseUrl: "https://git.example.com/" })).toMatchObject({
      authorization: "https://git.example.com/oauth/authorize",
      token: "https://git.example.com/oauth/token",
      userinfo: "https://git.example.com/api/v4/user",
      scopes: ["read_user"],
    });
  });

  it("maps the user", async () => {
    const identity = await defineGitLabProvider(secret).profile(
      context({ userinfo: fixtures.gitlabUser }),
    );
    expect(identity).toMatchObject({ subject: "1", name: "John Smith", email: "john@example.com" });
    expect(identity.emailVerified).toBeUndefined();
  });
});

describe("Twitch", () => {
  const provider = defineTwitchProvider(secret);

  it("sends the Client-Id header to Helix", () => {
    expectTypeOf(provider).toEqualTypeOf<OAuthProvider<TwitchProfile>>();
    expect(provider.userinfoHeaders).toEqual({ "client-id": "client-1" });
    expect(provider.scopes).toEqual(["user:read:email"]);
    expect(provider.pkce).toBe(false);
    expect(authorizationQuery(provider)).not.toHaveProperty("code_challenge");
  });

  it("unwraps data[0], whose email Twitch documents as verified", async () => {
    const identity = await provider.profile(context({ userinfo: fixtures.twitchUsers }));
    expect(identity).toMatchObject({
      subject: "141981764",
      name: "TwitchDev",
      email: "not-real@email.com",
      emailVerified: true,
    });
    expect(identity.profile).toBe(fixtures.twitchUsers.data[0]);
  });

  it("refuses an empty user list", async () => {
    const error = await rejection(provider.profile(context({ userinfo: { data: [] } })));
    expect(isUnauthError(error, "ERR_AUTHN_PROFILE_INVALID")).toBe(true);
  });
});

describe("LinkedIn", () => {
  const provider = defineLinkedInProvider(secret);

  it("is a discovered OpenID Connect provider with body client auth", () => {
    expectTypeOf(provider).toEqualTypeOf<OAuthProvider<LinkedInProfile>>();
    expect(provider).toMatchObject({
      kind: "oidc",
      issuer: "https://www.linkedin.com/oauth",
      tokenAuth: "body",
      discovery: true,
      pkce: false,
      nonce: true,
    });
    expect(defineLinkedInProvider({ ...secret, pkce: true }).pkce).toBe("S256");
  });

  it("maps the claims, keeping the object locale", async () => {
    const identity = await provider.profile(context({ claims: fixtures.linkedinClaims }));
    expect(identity).toMatchObject({
      subject: "782bbtaQ",
      name: "John Doe",
      email: "doe@email.com",
      emailVerified: true,
    });
    expect(identity.profile.locale).toEqual({ country: "US", language: "en" });
  });
});

describe("Facebook", () => {
  it("reads the Graph API with comma-separated scopes and the token in a header", () => {
    const provider = defineFacebookProvider(secret);
    expectTypeOf(provider).toEqualTypeOf<OAuthProvider<FacebookProfile>>();
    expect(provider.userinfo).toBe(
      "https://graph.facebook.com/v26.0/me?fields=id%2Cname%2Cemail%2Cpicture",
    );
    expect(authorizationQuery(provider).scope).toBe("email,public_profile");
    expect(provider.userinfo).not.toContain("access_token");
  });

  it("maps the user with its picture", async () => {
    const identity = await defineFacebookProvider(secret).profile(
      context({ userinfo: fixtures.facebookUser }),
    );
    expect(identity).toMatchObject({
      subject: "10224354126445211",
      name: "Ada Lovelace",
      email: "ada@example.com",
      avatar: fixtures.facebookUser.picture.data.url,
    });
  });
});

describe("X", () => {
  it("uses PKCE, Basic auth for confidential clients and none for public ones", () => {
    const confidential = defineXProvider(secret);
    expectTypeOf(confidential).toEqualTypeOf<OAuthProvider<XProfile>>();
    expect(confidential).toMatchObject({
      pkce: "S256",
      tokenAuth: "basic",
      scopes: ["users.read", "tweet.read"],
    });
    expect(defineXProvider({ clientId: "public" }).tokenAuth).toBe("none");
  });

  it("unwraps data", async () => {
    const identity = await defineXProvider(secret).profile(
      context({ userinfo: fixtures.xUsersMe }),
    );
    expect(identity).toMatchObject({
      subject: "2244994945",
      name: "Developers",
      avatar: fixtures.xUsersMe.data.profile_image_url,
    });
    expect(identity.email).toBeUndefined();
  });
});
