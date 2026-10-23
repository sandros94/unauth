import { beforeAll, beforeEach, describe, expect, expectTypeOf, it, vi } from "vitest";
import { type JWK_oct, defineJWESession, generateJWK } from "unjwt/session";

import {
  type AuthSessionData,
  type HandlerEvent,
  deriveKey,
  toSessionData,
} from "../../../src/n/index.ts";
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
    const definition = defineJWESession<AuthSessionData, "1h">({ key: flowKey, maxAge: "1h" });
    const session = (event: HandlerEvent) => definition.use(event);
    const config = { clientId: "gh-client", clientSecret: "gh-secret", label: "GH" };
    defineGitHubHandler({ ...config, key: flowKey, redirect: "/home", session });

    const [provider, signIn] = lastSignIn();
    expect(shape(provider)).toEqual(shape(defineGitHubProvider(config)));
    expect(signIn).toEqual({ key: flowKey, redirect: "/home", session });
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
  interface AppData extends AuthSessionData {
    role: string;
  }
  const config = { clientId: "c", clientSecret: "s" };

  it("takes a session util on data extending AuthSessionData, and answers with a Response", () => {
    const definition = defineJWESession<AppData, "1h">({ key: flowKey, maxAge: "1h" });
    const useAppSession = (event: HandlerEvent) => definition.use(event);
    const handler = defineGitHubHandler({ ...config, key: flowKey, session: useAppSession });

    expectTypeOf(handler).toEqualTypeOf<(event: HandlerEvent) => Promise<Response>>();
  });

  it("infers the session data from toSession and checks the util against it", () => {
    const definition = defineJWESession<AppData, "1h">({ key: flowKey, maxAge: "1h" });
    const useAppSession = (event: HandlerEvent) => definition.use(event);
    const handler = defineGitHubHandler({
      ...config,
      key: flowKey,
      session: useAppSession,
      toSession: (identity, context) => {
        expectTypeOf(identity.profile.login).toEqualTypeOf<string>();
        expectTypeOf(context).toEqualTypeOf<{ event: HandlerEvent; now: number }>();
        return { ...toSessionData(identity, context), role: "member" };
      },
      onSuccess: () => ({ ok: true }),
    });
    expectTypeOf(handler).returns.resolves.toEqualTypeOf<Response | { ok: boolean }>();

    const mismatched = {
      ...config,
      key: flowKey,
      session: useAppSession,
      toSession: () => ({ other: 1 }),
    };
    // @ts-expect-error the util does not take what toSession returns
    defineGitHubHandler(mismatched);
  });

  it("requires onSuccess without a session, and refuses toSession and redirect there", () => {
    const onSuccess = () => "ok";
    defineGitHubHandler({
      ...config,
      key: flowKey,
      onSuccess,
      // @ts-expect-error toSession needs a session to write
      toSession: () => ({}),
    });
    defineGitHubHandler({
      ...config,
      key: flowKey,
      onSuccess,
      // @ts-expect-error redirect is the default completion's, which needs a session
      redirect: "/home",
    });
    expectTypeOf(
      defineGitHubHandler({
        ...config,
        key: () => deriveKey(SECRET, { info: FLOW_INFO }),
        onSuccess,
      }),
    ).returns.resolves.toEqualTypeOf<Response | string>();
    expect(() =>
      // @ts-expect-error `onSuccess` is required without `session`
      defineGitHubHandler({ ...config, key: flowKey }),
    ).toThrow(expect.objectContaining({ code: "ERR_UNAUTH_CONFIG_INVALID" }));
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
