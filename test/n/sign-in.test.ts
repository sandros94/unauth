import { beforeAll, describe, expect, expectTypeOf, it, vi } from "vitest";
import {
  type JWK_oct,
  defineJWESession,
  exportPEM,
  generateJWK,
  importPEM,
  toPublicJWK,
} from "unjwt/session";
import { base64UrlParse } from "unjwt/utils";
import { hkdf } from "unsecure/hkdf";

import {
  type AuthSessionData,
  type CacheDriver,
  type FlowKey,
  type HandlerEvent,
  type Provider,
  type UnauthError,
  defineOidcProvider,
  defineSignInHandler,
  deriveKey,
  isUnauthError,
  defineOAuth2Provider,
  toSessionData,
} from "../../src/n/index.ts";
import { cookieJar } from "./_cookies.ts";
import { CLIENT_ID, CLIENT_SECRET, ISSUER, createFakeProvider } from "./flow/_fake-provider.ts";

vi.mock(import("unsecure/hkdf"), async (original) => {
  const actual = await original();
  return { ...actual, hkdf: vi.fn(actual.hkdf) as typeof actual.hkdf };
});

const APP = "http://localhost";
const REDIRECT_URI = `${APP}/auth/fake`;
const SECRET = "a-flow-secret-of-at-least-32-characters";
const FLOW_INFO = "unauth:flow";
const NOW = Date.UTC(2026, 9, 22, 12);

let key: JWK_oct<"A256GCM">;
let flowKey: JWK_oct<"A256GCM">;

beforeAll(async () => {
  key = await generateJWK("A256GCM");
  flowKey = await generateJWK("A256GCM");
});

interface User {
  userId: string;
  role?: string;
}

function fakeProvider(options: { responseMode?: "query" | "form_post" } = {}): Provider {
  return defineOAuth2Provider({
    id: "fake",
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    authorization: `${ISSUER}/authorize`,
    token: `${ISSUER}/token`,
    userinfo: `${ISSUER}/userinfo`,
    ...options,
  });
}

/** A web-standard event for `request`, with the `Headers` its response is sent with. */
function eventFor(request: Request): HandlerEvent & { res: { headers: Headers } } {
  return { req: request, res: { headers: new Headers() }, context: {} };
}

/** Runs a handler and turns what it returns into a `Response`, the way a runtime would. */
async function call(
  handler: (event: HandlerEvent) => Promise<unknown>,
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  const event = eventFor(new Request(`${APP}${path}`, init));
  const result = await handler(event);
  if (result instanceof Response) {
    for (const line of event.res.headers.getSetCookie()) result.headers.append("set-cookie", line);
    return result;
  }
  return new Response(JSON.stringify(result), {
    headers: new Headers([...event.res.headers, ["content-type", "application/json"]]),
  });
}

describe("defineSignInHandler without a session", () => {
  let fake: Awaited<ReturnType<typeof createFakeProvider>>;

  async function setup(
    overrides: Pick<Parameters<typeof defineSignInHandler>[1], "onStart" | "onError"> = {},
  ) {
    fake = await createFakeProvider();
    const auth = defineJWESession<User>({ key, name: "unauth", cookie: { secure: false } });
    const handler = defineSignInHandler(fakeProvider(), {
      key: flowKey,
      cookie: { secure: false },
      redirectUri: REDIRECT_URI,
      fetch: fake.fetch,
      onSuccess: async (event, result) => {
        const session = await auth.use(event);
        await session.update({ userId: result.identity.subject });
        return { subject: result.identity.subject, redirect: result.redirect ?? null };
      },
      ...overrides,
    });
    return { auth, handler };
  }

  async function signInFlow(handler: (event: HandlerEvent) => Promise<unknown>, jar = cookieJar()) {
    const start = await call(handler, "/auth/fake");
    jar.update(start.headers);
    const back = fake.approve(start.headers.get("location")!);
    const done = await call(handler, `${back.pathname}${back.search}`, {
      headers: { cookie: jar.toString() },
    });
    jar.update(done.headers);
    return { start, back, done, jar };
  }

  it("hands a cache driver to both legs: discovery on the first, the JWK Set on the second", async () => {
    const sets: string[] = [];
    const held = new Map<string, unknown>();
    const driver: CacheDriver = {
      // oxlint-disable-next-line typescript/no-unnecessary-type-parameters -- CacheDriver's own signature
      get: <T>(name: string): T | null => (held.get(name) ?? null) as T | null,
      set: (name, value) => {
        sets.push(name);
        held.set(name, value);
      },
    };
    const oidc = defineOidcProvider({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
    });
    fake = await createFakeProvider();
    const handler = defineSignInHandler(oidc, {
      key: flowKey,
      cookie: { secure: false },
      redirectUri: REDIRECT_URI,
      fetch: fake.fetch,
      cache: driver,
      onSuccess: (_event, result) => result.identity.subject,
    });

    const { done } = await signInFlow(handler);

    expect(done.status).toBe(200);
    expect(sets.map((name) => name.split(":")[1])).toEqual(["discovery", "jwks"]);
  });

  it("answers the first leg with a redirect to the provider and a flow cookie", async () => {
    const { handler } = await setup();
    const start = await call(handler, "/auth/fake");

    expect(start.status).toBe(302);
    expect(new URL(start.headers.get("location")!).origin).toBe(ISSUER);
    expect(start.headers.getSetCookie().join("\n")).toMatch(/unauth-flow=/);
  });

  it("completes the callback leg, expires the flow cookie and hands the result to onSuccess", async () => {
    const { auth, handler } = await setup();
    const { done, jar } = await signInFlow(handler);

    expect(done.status).toBe(200);
    expect(await done.json()).toEqual({ subject: "user-1", redirect: null });
    const cookies = done.headers.getSetCookie();
    expect(cookies.some((line) => /^unauth-flow=[^;]*;.*Max-Age=0/i.test(line))).toBe(true);
    expect(cookies.some((line) => line.startsWith("unauth="))).toBe(true);

    const session = await auth.use(
      eventFor(new Request(APP, { headers: { cookie: jar.toString() } })),
    );
    expect(session.id).toEqual(expect.any(String));
    expect(session.data).toMatchObject({ userId: "user-1" });
  });

  it("passes onStart's intent through the flow", async () => {
    const { handler } = await setup({ onStart: () => ({ redirect: "/dashboard" }) });
    const { done } = await signInFlow(handler);

    expect(await done.json()).toEqual({ subject: "user-1", redirect: "/dashboard" });
  });

  it("answers an UnauthError with its status and message, the flow cookie expired on that response", async () => {
    const { handler } = await setup();
    const jar = cookieJar();
    const start = await call(handler, "/auth/fake");
    jar.update(start.headers);
    const back = fake.approve(start.headers.get("location")!);
    back.searchParams.set("state", "forged");

    const event = eventFor(new Request(back, { headers: { cookie: jar.toString() } }));
    const res = await handler(event);

    expect(res).toBeInstanceOf(Response);
    const response = res as Response;
    expect(response.status).toBe(401);
    expect(await response.text()).toMatch(/does not belong/);
    expect(response.headers.getSetCookie().join("\n")).toMatch(/unauth-flow=/);
    expect(event.res.headers.getSetCookie()).toEqual([]);
  });

  it("hands UnauthErrors to onError when given, the flow cookie expired on the event", async () => {
    const onError = vi.fn((_event: HandlerEvent, error: unknown) => ({
      failed: isUnauthError(error) && error.code,
    }));
    const { handler } = await setup({ onError });
    const jar = cookieJar();
    const start = await call(handler, "/auth/fake");
    jar.update(start.headers);
    const back = fake.approve(start.headers.get("location")!);
    back.searchParams.set("error", "access_denied");

    const event = eventFor(new Request(back, { headers: { cookie: jar.toString() } }));
    const result = await handler(event);

    expect(result).toEqual({ failed: "ERR_AUTHN_PROVIDER_REFUSED" });
    expect(onError).toHaveBeenCalledOnce();
    expect(event.res.headers.getSetCookie().join("\n")).toMatch(/unauth-flow=/);
  });

  it("hides configuration details behind a 500", async () => {
    fake = await createFakeProvider();
    const handler = defineSignInHandler(fakeProvider(), { key: flowKey, onSuccess: () => "ok" });

    const res = await call(handler, "/auth/fake");

    expect(res.status).toBe(500);
    expect(await res.text()).not.toContain("redirectUri");
  });

  it("completes a form_post callback posted to the same route", async () => {
    fake = await createFakeProvider();
    const handler = defineSignInHandler(fakeProvider({ responseMode: "form_post" }), {
      key: flowKey,
      redirectUri: REDIRECT_URI,
      fetch: fake.fetch,
      onSuccess: (_event, result) => ({ subject: result.identity.subject }),
    });
    const jar = cookieJar();
    const start = await call(handler, "/auth/fake");
    jar.update(start.headers);
    const back = fake.approve(start.headers.get("location")!);

    const done = await call(handler, "/auth/fake", {
      method: "POST",
      headers: { "cookie": jar.toString(), "content-type": "application/x-www-form-urlencoded" },
      body: back.searchParams.toString(),
    });

    expect(done.status).toBe(200);
    expect(await done.json()).toEqual({ subject: "user-1" });
  });

  it("rethrows anything that is not an UnauthError", async () => {
    const { handler } = await setup({
      onStart: () => {
        throw new TypeError("boom");
      },
    });

    await expect(call(handler, "/auth/fake")).rejects.toThrow(TypeError);
  });
});

describe("defineSignInHandler with a session", () => {
  let fake: Awaited<ReturnType<typeof createFakeProvider>>;
  let auth: ReturnType<typeof defineJWESession<AuthSessionData, "1h">>;

  beforeAll(() => {
    auth = defineJWESession<AuthSessionData, "1h">({
      key,
      name: "unauth",
      maxAge: "1h",
      cookie: { secure: false },
    });
  });

  const useAuthSession = (event: HandlerEvent) => auth.use(event);

  async function signInFlow(
    handler: (event: HandlerEvent) => Promise<unknown>,
    path = "/auth/fake",
  ) {
    const jar = cookieJar();
    const start = await call(handler, path);
    jar.update(start.headers);
    const back = fake.approve(start.headers.get("location")!);
    const done = await call(handler, `${back.pathname}${back.search}`, {
      headers: { cookie: jar.toString() },
    });
    jar.update(done.headers);
    const session = await auth.use(
      eventFor(new Request(APP, { headers: { cookie: jar.toString() } })),
    );
    return { start, done, session };
  }

  const base = () => ({
    key: flowKey,
    cookie: { secure: false },
    redirectUri: REDIRECT_URI,
    fetch: fake.fetch,
    now: () => NOW,
  });

  beforeAll(async () => {
    fake = await createFakeProvider();
  });

  it("writes the identity's AuthSessionData and lands on / without caching", async () => {
    const handler = defineSignInHandler(fakeProvider(), { ...base(), session: useAuthSession });
    const { done, session } = await signInFlow(handler);

    expect(done.status).toBe(302);
    expect(done.headers.get("location")).toBe("/");
    expect(done.headers.get("cache-control")).toBe("no-store");
    const cookies = done.headers.getSetCookie();
    expect(cookies.some((line) => /^unauth-flow=[^;]*;.*Max-Age=0/i.test(line))).toBe(true);
    expect(session.data).toEqual({
      provider: "fake",
      subject: "user-1",
      name: "Ada",
      email: "ada@idp.test",
      emailVerified: true,
      signedInAt: NOW,
    });
  });

  it("replaces the session another user left behind, id included", async () => {
    const handler = defineSignInHandler(fakeProvider(), { ...base(), session: useAuthSession });
    const jar = cookieJar();
    const seeded = eventFor(new Request(APP));
    const before = await auth.use(seeded);
    await before.update({
      provider: "old",
      subject: "mallory",
      name: "Mallory",
      avatar: "https://idp.test/mallory.png",
      signedInAt: 1,
    });
    jar.update(seeded.res.headers);

    const start = await call(handler, "/auth/fake", { headers: { cookie: jar.toString() } });
    jar.update(start.headers);
    const back = fake.approve(start.headers.get("location")!);
    const done = await call(handler, `${back.pathname}${back.search}`, {
      headers: { cookie: jar.toString() },
    });
    jar.update(done.headers);
    const after = await auth.use(
      eventFor(new Request(APP, { headers: { cookie: jar.toString() } })),
    );

    expect(after.id).not.toBe(before.id);
    expect(after.data).toEqual({
      provider: "fake",
      subject: "user-1",
      name: "Ada",
      email: "ada@idp.test",
      emailVerified: true,
      signedInAt: NOW,
    });
    expect(Object.hasOwn(after.data, "avatar")).toBe(false);
  });

  it("lands on `redirect`, unless the flow carries a same-origin one", async () => {
    const plain = defineSignInHandler(fakeProvider(), {
      ...base(),
      session: useAuthSession,
      redirect: "/home",
    });
    expect((await signInFlow(plain)).done.headers.get("location")).toBe("/home");

    const intent = defineSignInHandler(fakeProvider(), {
      ...base(),
      session: useAuthSession,
      redirect: "/home",
      onStart: () => ({ redirect: "/after" }),
    });
    expect((await signInFlow(intent)).done.headers.get("location")).toBe("/after");

    const open = defineSignInHandler(fakeProvider(), {
      ...base(),
      session: useAuthSession,
      redirect: "/home",
      onStart: () => ({ redirect: "//evil.test/" }),
    });
    expect((await signInFlow(open)).done.headers.get("location")).toBe("/home");
  });

  it("writes what an async toSession returns", async () => {
    interface AppData extends AuthSessionData {
      role: string;
    }
    const app = defineJWESession<AppData, "1h">({
      key,
      name: "unauth",
      maxAge: "1h",
      cookie: { secure: false },
    });
    const handler = defineSignInHandler(fakeProvider(), {
      ...base(),
      session: (event: HandlerEvent) => app.use(event),
      toSession: async (identity, { now }) => {
        await Promise.resolve();
        return { ...toSessionData(identity, { now }), role: "member" };
      },
    });
    const { session } = await signInFlow(handler);

    expect(session.data).toMatchObject({ subject: "user-1", role: "member", signedInAt: NOW });
  });

  it("runs onSuccess after the write and answers with its value", async () => {
    const handler = defineSignInHandler(fakeProvider(), {
      ...base(),
      session: useAuthSession,
      onSuccess: async (event) => {
        const current = await useAuthSession(event);
        return { written: current.data.subject };
      },
    });
    const { done, session } = await signInFlow(handler);

    expect(done.status).toBe(200);
    expect(await done.json()).toEqual({ written: "user-1" });
    expect(session.data.subject).toBe("user-1");
  });

  it("hands the refusal of a link intent to onError at the start leg", async () => {
    const errors: UnauthError[] = [];
    const reported = defineSignInHandler(fakeProvider(), {
      ...base(),
      session: useAuthSession,
      onStart: () => ({ link: { userId: "u1" } }),
      onError: (_event, error) => {
        errors.push(error);
        return new Response(null, { status: 409 });
      },
    });

    const start = await call(reported, "/auth/fake");

    expect(start.status).toBe(409);
    expect(errors.map((error) => error.code)).toEqual(["ERR_UNAUTH_CONFIG_INVALID"]);
    expect(errors[0]!.message).toMatch(/`link` intent needs `onSuccess`/);
  });

  it("refuses a link intent at the start leg, before any redirect or flow cookie", async () => {
    const handler = defineSignInHandler(fakeProvider(), {
      ...base(),
      session: useAuthSession,
      onStart: () => ({ link: { userId: "u1" } }),
    });
    const served = fake.requests.length;

    const start = await call(handler, "/auth/fake");

    expect(start.status).toBe(500);
    expect(start.headers.get("location")).toBeNull();
    expect(start.headers.getSetCookie()).toEqual([]);
    expect(fake.requests).toHaveLength(served);
  });

  it("hands a link intent to onSuccess without touching the session", async () => {
    const handler = defineSignInHandler(fakeProvider(), {
      ...base(),
      session: useAuthSession,
      onStart: () => ({ link: { userId: "u1" } }),
      onSuccess: (_event, result) => ({ link: result.link }),
    });
    const { done, session } = await signInFlow(handler);

    expect(await done.json()).toEqual({ link: { userId: "u1" } });
    expect(session.id).toBeUndefined();
  });

  it("resolves a key callback once across sign-ins", async () => {
    vi.mocked(hkdf).mockClear();
    const handler = defineSignInHandler(fakeProvider(), {
      ...base(),
      key: () => deriveKey(SECRET, { info: FLOW_INFO }),
      session: useAuthSession,
    });

    expect(vi.mocked(hkdf)).not.toHaveBeenCalled();
    expect((await signInFlow(handler)).session.data.subject).toBe("user-1");
    expect((await signInFlow(handler)).session.data.subject).toBe("user-1");
    const derivations = vi
      .mocked(hkdf)
      .mock.calls.filter(([, options]) => options?.info === FLOW_INFO);
    expect(derivations).toHaveLength(1);
  });

  it("answers a key callback's string through onError, before any redirect", async () => {
    const errors: UnauthError[] = [];
    const stringKey = (): FlowKey => {
      // @ts-expect-error a string is not a key
      return SECRET;
    };
    const handler = defineSignInHandler(fakeProvider(), {
      ...base(),
      key: stringKey,
      session: useAuthSession,
      onError: (_event, error) => {
        errors.push(error);
        return new Response(null, { status: 500 });
      },
    });

    const start = await call(handler, "/auth/fake");

    expect(start.status).toBe(500);
    expect(start.headers.get("location")).toBeNull();
    expect(errors.map((error) => error.code)).toEqual(["ERR_UNAUTH_CONFIG_INVALID"]);
    expect(errors[0]!.message).toMatch(/importPEM\(pem, alg\)[\s\S]*deriveKey/);
  });

  it("seals the flow with an asymmetric pair imported from a PEM", async () => {
    const alg = "RSA-OAEP-256";
    const pair = await generateJWK(alg);
    const pem = await exportPEM(pair.privateKey);
    const handler = defineSignInHandler(fakeProvider(), {
      ...base(),
      key: async () => {
        const privateKey = await importPEM(pem, alg, { pemType: "pkcs8" });
        return { privateKey, publicKey: toPublicJWK(privateKey) };
      },
      session: useAuthSession,
    });

    const { start, session } = await signInFlow(handler);

    const flowCookie = start.headers
      .getSetCookie()
      .find((line) => line.startsWith("unauth-flow="))!;
    const token = flowCookie.slice("unauth-flow=".length).split(";", 1)[0]!;
    const header = JSON.parse(base64UrlParse(token.split(".", 1)[0]!)) as {
      alg: string;
      typ: string;
    };
    expect(header.alg).toBe(alg);
    expect(header.alg).not.toBe("dir");
    expect(header.typ).toBe("unauth-flow+jwt");
    expect(session.data.subject).toBe("user-1");
  });

  it("derives redirect_uri from a request on `origin`, and refuses another origin", async () => {
    const errors: UnauthError[] = [];
    const handler = defineSignInHandler(fakeProvider(), {
      ...base(),
      redirectUri: undefined,
      origin: APP,
      session: useAuthSession,
      onError: (_event, error) => {
        errors.push(error);
        return new Response(null, { status: 500 });
      },
    });
    fake.requests.length = 0;
    const { start, session } = await signInFlow(handler, "/auth/fake?ignored=1");

    const authorize = new URL(start.headers.get("location")!);
    expect(authorize.searchParams.get("redirect_uri")).toBe(`${APP}/auth/fake`);
    const token = fake.requests.find((request) => request.url.pathname === "/token")!;
    expect(new URLSearchParams(token.body).get("redirect_uri")).toBe(`${APP}/auth/fake`);
    expect(session.data.subject).toBe("user-1");

    const other = await handler(eventFor(new Request("https://evil.test/auth/fake")));
    expect(other.status).toBe(500);
    expect(errors.map((error) => error.code)).toEqual(["ERR_UNAUTH_CONFIG_INVALID"]);
  });

  it("refuses a bad key, origin or redirect where the route is defined", () => {
    const refusal = (define: () => unknown) => {
      try {
        define();
      } catch (error) {
        return isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID");
      }
      return false;
    };
    const rest = { cookie: { secure: false as const }, fetch: fake.fetch, session: useAuthSession };

    // @ts-expect-error a string is not a key
    expect(refusal(() => defineSignInHandler(fakeProvider(), { ...rest, key: SECRET }))).toBe(true);
    // @ts-expect-error `key` is required
    expect(refusal(() => defineSignInHandler(fakeProvider(), rest))).toBe(true);
    expect(
      refusal(() =>
        defineSignInHandler(fakeProvider(), { ...rest, key: flowKey, origin: "app.test" }),
      ),
    ).toBe(true);
    expect(
      refusal(() =>
        defineSignInHandler(fakeProvider(), {
          ...rest,
          key: flowKey,
          redirect: "https://evil.test/",
        }),
      ),
    ).toBe(true);
    expect(
      refusal(() =>
        defineSignInHandler(fakeProvider(), { ...rest, key: flowKey, redirect: "//evil.test" }),
      ),
    ).toBe(true);
    expect(
      refusal(() =>
        defineSignInHandler(fakeProvider(), { ...rest, key: flowKey, redirect: "/home" }),
      ),
    ).toBe(false);
  });

  it("refuses a sign-in with neither a session nor onSuccess", () => {
    expect(() =>
      // @ts-expect-error `onSuccess` is required without `session`
      defineSignInHandler(fakeProvider(), { key: flowKey, redirectUri: REDIRECT_URI }),
    ).toThrow(expect.objectContaining({ code: "ERR_UNAUTH_CONFIG_INVALID" }));
  });
});

describe("defineSignInHandler types", () => {
  interface AppData extends AuthSessionData {
    role: string;
  }

  it("takes a session util on data extending AuthSessionData, and answers with a Response", () => {
    const definition = defineJWESession<AppData, "1h">({ key: flowKey, maxAge: "1h" });
    const useAppSession = (event: HandlerEvent) => definition.use(event);
    const handler = defineSignInHandler(fakeProvider(), { key: flowKey, session: useAppSession });

    expectTypeOf(handler).toEqualTypeOf<(event: HandlerEvent) => Promise<Response>>();
  });

  it("infers the session data from toSession and checks the util against it", () => {
    const definition = defineJWESession<AppData, "1h">({ key: flowKey, maxAge: "1h" });
    const useAppSession = (event: HandlerEvent) => definition.use(event);
    const handler = defineSignInHandler(fakeProvider(), {
      key: flowKey,
      session: useAppSession,
      toSession: (identity, context) => {
        expectTypeOf(context).toEqualTypeOf<{ event: HandlerEvent; now: number }>();
        return { ...toSessionData(identity, context), role: "member" };
      },
      onSuccess: () => ({ ok: true }),
    });
    expectTypeOf(handler).returns.resolves.toEqualTypeOf<Response | { ok: boolean }>();

    const mismatched = { key: flowKey, session: useAppSession, toSession: () => ({ other: 1 }) };
    // @ts-expect-error the util does not take what toSession returns
    defineSignInHandler(fakeProvider(), mismatched);
  });

  it("requires onSuccess without a session, and refuses toSession and redirect there", () => {
    const onSuccess = () => "ok";
    defineSignInHandler(fakeProvider(), {
      key: flowKey,
      onSuccess,
      // @ts-expect-error toSession needs a session to write
      toSession: () => ({}),
    });
    defineSignInHandler(fakeProvider(), {
      key: flowKey,
      onSuccess,
      // @ts-expect-error redirect is the default completion's, which needs a session
      redirect: "/home",
    });
    expectTypeOf(
      defineSignInHandler(fakeProvider(), {
        key: () => deriveKey(SECRET, { info: FLOW_INFO }),
        onSuccess,
      }),
    ).returns.resolves.toEqualTypeOf<Response | string>();
  });
});
