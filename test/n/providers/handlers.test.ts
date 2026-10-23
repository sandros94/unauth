import { beforeAll, beforeEach, describe, expect, expectTypeOf, it, vi } from "vitest";
import { type JWK_oct, defineJWESession, generateJWK } from "unjwt/session";

import { type WebRequestEvent, deriveKey } from "../../../src/n/index.ts";
import { defineSignInHandler } from "../../../src/n/sign-in.ts";
import { presetHandler } from "../../../src/n/providers/_shared.ts";
import { defineAppleHandler, defineAppleProvider } from "../../../src/n/providers/apple.ts";
import { defineDiscordHandler, defineDiscordProvider } from "../../../src/n/providers/discord.ts";
import {
  defineFacebookHandler,
  defineFacebookProvider,
} from "../../../src/n/providers/facebook.ts";
import {
  type GitHubProviderConfig,
  defineGitHubHandler,
  defineGitHubProvider,
} from "../../../src/n/providers/github.ts";
import { defineGitLabHandler, defineGitLabProvider } from "../../../src/n/providers/gitlab.ts";
import { defineGoogleHandler, defineGoogleProvider } from "../../../src/n/providers/google.ts";
import {
  defineLinkedInHandler,
  defineLinkedInProvider,
} from "../../../src/n/providers/linkedin.ts";
import {
  defineMicrosoftHandler,
  defineMicrosoftProvider,
} from "../../../src/n/providers/microsoft.ts";
import { defineTwitchHandler, defineTwitchProvider } from "../../../src/n/providers/twitch.ts";
import { defineXHandler, defineXProvider } from "../../../src/n/providers/x.ts";
import { cookieHeader } from "../_session.ts";

vi.mock(import("../../../src/n/sign-in.ts"), async (original) => {
  const actual = await original();
  return {
    ...actual,
    defineSignInHandler: vi.fn(
      actual.defineSignInHandler,
    ) as unknown as typeof actual.defineSignInHandler,
  };
});

const APP = "http://localhost";
const SECRET = "a-flow-secret-of-at-least-32-characters";
const FLOW_INFO = "unauth:flow";

let flowKey: JWK_oct<"A256GCM">;

interface AppSession {
  userId: string;
}

beforeAll(async () => {
  flowKey = await generateJWK("A256GCM");
});

beforeEach(() => {
  vi.mocked(defineSignInHandler).mockClear();
});

/** What `defineSignInHandler` was last given: the provider and the sign-in options. */
function lastSignIn(): [unknown, unknown] {
  const call = vi.mocked(defineSignInHandler).mock.lastCall;
  if (!call) throw new Error("defineSignInHandler was not called");
  return [call[0], call[1]];
}

/** `value` with its functions replaced by a marker, so two definitions compare by their data. */
function shape(value: unknown): unknown {
  return JSON.parse(
    JSON.stringify(value, (_key, member) => (typeof member === "function" ? "fn" : member)),
  );
}

describe("defineGitHubHandler", () => {
  it("redirects to GitHub with the provider's options and the callback derived from origin", async () => {
    const handler = defineGitHubHandler({
      clientId: "gh-client",
      clientSecret: "gh-secret",
      scopes: ["read:user"],
      id: "gh",
      label: "GH",
      key: () => deriveKey(SECRET, { info: FLOW_INFO }),
      origin: APP,
      cookie: { secure: false },
      onSuccess: () => "ok",
    });
    const event = { req: new Request(`${APP}/auth/github`), res: { headers: new Headers() } };
    const start = await handler(event);

    expect(start).toBeInstanceOf(Response);
    const response = start as Response;
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location")!);
    expect(location.origin + location.pathname).toBe("https://github.com/login/oauth/authorize");
    expect(location.searchParams.get("client_id")).toBe("gh-client");
    expect(location.searchParams.get("scope")).toBe("read:user");
    expect(location.searchParams.get("redirect_uri")).toBe(`${APP}/auth/github`);
    expect(cookieHeader(response.headers)).toMatch(/^unauth-flow=/);

    const [provider] = lastSignIn();
    expect(provider).toMatchObject({ id: "gh", label: "GH", client: { id: "gh-client" } });
  });

  it("hands the provider its options only, and the sign-in the others", () => {
    const onSuccess = () => {};
    const config = { clientId: "gh-client", clientSecret: "gh-secret", label: "GH" };
    defineGitHubHandler({ ...config, key: flowKey, redirect: "/home", onSuccess });

    const [provider, signIn] = lastSignIn();
    expect(shape(provider)).toEqual(shape(defineGitHubProvider(config)));
    expect(signIn).toEqual({ key: flowKey, redirect: "/home", onSuccess });
  });
});

describe("every preset handler", () => {
  const common = {
    id: "custom",
    label: "Custom",
    scopes: ["openid", "two"],
    authorizationParams: { prompt: "consent" },
  };
  const signIn = {
    key: () => deriveKey(SECRET, { info: FLOW_INFO }),
    origin: APP,
    onSuccess: () => "ok",
  };
  const apple = { ...common, clientId: "c", teamId: "t", keyId: "k", privateKey: "pem" };
  const oauth = { ...common, clientId: "c", clientSecret: "s" };
  const facebook = { ...oauth, version: "v1.0", fields: ["id"] };
  const gitlab = { ...oauth, baseUrl: "https://git.test" };
  const linkedin = { ...oauth, pkce: true };
  const microsoft = { ...oauth, tenant: "organizations" };
  const cases = [
    {
      name: "apple",
      handler: () => defineAppleHandler({ ...apple, ...signIn }),
      provider: () => defineAppleProvider(apple),
    },
    {
      name: "discord",
      handler: () => defineDiscordHandler({ ...oauth, ...signIn }),
      provider: () => defineDiscordProvider(oauth),
    },
    {
      name: "facebook",
      handler: () => defineFacebookHandler({ ...facebook, ...signIn }),
      provider: () => defineFacebookProvider(facebook),
    },
    {
      name: "github",
      handler: () => defineGitHubHandler({ ...oauth, ...signIn }),
      provider: () => defineGitHubProvider(oauth),
    },
    {
      name: "gitlab",
      handler: () => defineGitLabHandler({ ...gitlab, ...signIn }),
      provider: () => defineGitLabProvider(gitlab),
    },
    {
      name: "google",
      handler: () => defineGoogleHandler({ ...oauth, ...signIn }),
      provider: () => defineGoogleProvider(oauth),
    },
    {
      name: "linkedin",
      handler: () => defineLinkedInHandler({ ...linkedin, ...signIn }),
      provider: () => defineLinkedInProvider(linkedin),
    },
    {
      name: "microsoft",
      handler: () => defineMicrosoftHandler({ ...microsoft, ...signIn }),
      provider: () => defineMicrosoftProvider(microsoft),
    },
    {
      name: "twitch",
      handler: () => defineTwitchHandler({ ...oauth, ...signIn }),
      provider: () => defineTwitchProvider(oauth),
    },
    {
      name: "x",
      handler: () => defineXHandler({ ...oauth, ...signIn }),
      provider: () => defineXProvider(oauth),
    },
  ];

  it.each(cases)("$name: every config member reaches the provider, nothing else", (entry) => {
    entry.handler();

    const [given, options] = lastSignIn();
    expect(shape(given)).toEqual(shape(entry.provider()));
    expect(options).toEqual(signIn);
  });
});

describe("preset handler types", () => {
  const config = { clientId: "c", clientSecret: "s" };
  const useAppSession = (event: WebRequestEvent) =>
    defineJWESession<AppSession, "1h">({ key: flowKey, maxAge: "1h" }).use(event);

  it("infers TResult from onSuccess, and requires it", () => {
    expectTypeOf(
      defineGitHubHandler({
        ...config,
        key: () => deriveKey(SECRET, { info: FLOW_INFO }),
        onSuccess: () => "ok",
      }),
    ).returns.resolves.toEqualTypeOf<Response | string>();
    expect(() =>
      // @ts-expect-error `onSuccess` is required
      defineGitHubHandler({ ...config, key: flowKey }),
    ).toThrow(expect.objectContaining({ code: "ERR_UNAUTH_CONFIG_INVALID" }));
  });

  it("types result.link as the payload onStart returns", () => {
    defineGitHubHandler({
      ...config,
      key: flowKey,
      onStart: async (event) => {
        const session = await useAppSession(event);
        return session.id ? { link: { userId: session.data.userId, from: "settings" } } : undefined;
      },
      onSuccess: (_event, result) => {
        expectTypeOf(result.link).toEqualTypeOf<{ userId: string; from: string } | undefined>();
        expectTypeOf(result.identity.profile.login).toEqualTypeOf<string>();
      },
    });
    defineGitHubHandler({
      ...config,
      key: flowKey,
      onSuccess: (_event, result) => {
        expectTypeOf<NonNullable<typeof result.link>>().toBeNever();
      },
    });
  });

  it("requires the provider's own options", () => {
    expect(() =>
      // @ts-expect-error `clientSecret` is GitHub's
      defineGitHubHandler({ clientId: "c", key: flowKey, onSuccess: () => "ok" }),
    ).toThrow(expect.objectContaining({ code: "ERR_UNAUTH_CONFIG_INVALID" }));
  });

  it("refuses a preset key list missing a config member or naming another", () => {
    const exact = [
      "clientId",
      "clientSecret",
      "scopes",
      "authorizationParams",
      "id",
      "label",
    ] as const;
    expectTypeOf<(typeof exact)[number]>().toEqualTypeOf<keyof GitHubProviderConfig>();
    presetHandler(defineGitHubProvider, { keys: exact });
    presetHandler(defineGitHubProvider, {
      // @ts-expect-error `label` is missing
      keys: ["clientId", "clientSecret", "scopes", "authorizationParams", "id"],
    });
    presetHandler(defineGitHubProvider, {
      // @ts-expect-error `key` is the sign-in's
      keys: ["clientId", "clientSecret", "scopes", "authorizationParams", "id", "label", "key"],
    });
  });
});
