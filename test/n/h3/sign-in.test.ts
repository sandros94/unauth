import { beforeAll, describe, expect, expectTypeOf, it } from "vitest";
import { H3, type H3Event, HTTPError } from "h3";
import { type JWK_oct, defineJWESession, generateJWK } from "unjwt/session";

import {
  type Provider,
  type WebRequestEvent,
  defineSignInHandler,
  defineOAuth2Provider,
} from "../../../src/n/index.ts";
import { type GitHubProfile, defineGitHubHandler } from "../../../src/n/providers/github.ts";
import { cookieJar } from "../_cookies.ts";
import { CLIENT_ID, CLIENT_SECRET, ISSUER, createFakeProvider } from "../flow/_fake-provider.ts";

const REDIRECT_URI = "http://localhost/auth/fake";

let key: JWK_oct<"A256GCM">;
let flowKey: JWK_oct<"A256GCM">;

beforeAll(async () => {
  key = await generateJWK("A256GCM");
  flowKey = await generateJWK("A256GCM");
});

interface User {
  userId: string;
}

interface SignedIn {
  provider: string;
  subject: string;
}

function fakeProvider(): Provider {
  return defineOAuth2Provider({
    id: "fake",
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    authorization: `${ISSUER}/authorize`,
    token: `${ISSUER}/token`,
    userinfo: `${ISSUER}/userinfo`,
  });
}

/** The handler's event is the h3 event as it is: no adapter, no `h3` dependency in `unauth`. */
describe("h3 v2", () => {
  let app: H3;
  let fake: Awaited<ReturnType<typeof createFakeProvider>>;

  async function setup() {
    fake = await createFakeProvider();
    const auth = defineJWESession<User, undefined, H3Event>({ key, name: "__Host-unauth" });
    app = new H3();
    app.get(
      "/auth/fake",
      defineSignInHandler(fakeProvider(), {
        key: flowKey,
        redirectUri: REDIRECT_URI,
        fetch: fake.fetch,
        onSuccess: async (event: H3Event, result) => {
          const session = await auth.use(event);
          await session.update({ userId: result.identity.subject });
          return { subject: result.identity.subject, redirect: result.redirect ?? null };
        },
      }),
    );
    app.get("/me", async (event) => {
      const session = await auth.use(event);
      if (!session.id) throw new HTTPError({ status: 401 });
      return session.data;
    });
  }

  async function signInFlow(jar = cookieJar()) {
    const start = await app.request("/auth/fake");
    jar.update(start.headers);
    const back = fake.approve(start.headers.get("location")!);
    const done = await app.request(`${back.pathname}${back.search}`, {
      headers: { cookie: jar.toString() },
    });
    jar.update(done.headers);
    return { start, back, done, jar };
  }

  it("runs both legs of a sign-in on the h3 event", async () => {
    await setup();
    const start = await app.request("/auth/fake");
    expect(start.status).toBe(302);
    expect(new URL(start.headers.get("location")!).origin).toBe(ISSUER);
    expect(start.headers.getSetCookie().join("\n")).toMatch(/__Host-unauth-flow=/);

    const { done, jar } = await signInFlow();
    expect(done.status).toBe(200);
    expect(await done.json()).toEqual({ subject: "user-1", redirect: null });
    const cookies = done.headers.getSetCookie();
    expect(cookies.some((line) => /^__Host-unauth-flow=[^;]*;.*Max-Age=0/i.test(line))).toBe(true);
    expect(cookies.some((line) => line.startsWith("__Host-unauth="))).toBe(true);

    const me = await app.request("/me", { headers: { cookie: jar.toString() } });
    expect(me.status).toBe(200);
    expect(await me.json()).toMatchObject({ userId: "user-1" });
  });

  it("answers a failed callback with the error's status, the flow cookie expired", async () => {
    await setup();
    const jar = cookieJar();
    const start = await app.request("/auth/fake");
    jar.update(start.headers);
    const back = fake.approve(start.headers.get("location")!);
    back.searchParams.set("state", "forged");

    const res = await app.request(`${back.pathname}${back.search}`, {
      headers: { cookie: jar.toString() },
    });

    expect(res.status).toBe(401);
    expect(res.headers.getSetCookie().join("\n")).toMatch(/__Host-unauth-flow=/);
  });

  it("expires the flow cookie when onError answers an error Response or throws: h3 keeps those headers apart", async () => {
    fake = await createFakeProvider();
    const errors = new H3();
    errors.all(
      "/auth/fake",
      defineSignInHandler(fakeProvider(), {
        key: flowKey,
        redirectUri: REDIRECT_URI,
        fetch: fake.fetch,
        onSuccess: () => "ok",
        onError: (event: H3Event, error) => {
          if (event.url.searchParams.has("throw")) throw new HTTPError({ status: 401 });
          return new Response(error.message, { status: error.status });
        },
      }),
    );
    for (const mode of ["", "&throw=1"]) {
      const jar = cookieJar();
      const start = await errors.request("/auth/fake");
      jar.update(start.headers);
      const back = fake.approve(start.headers.get("location")!);
      back.searchParams.set("state", "forged");

      const res = await errors.request(`${back.pathname}${back.search}${mode}`, {
        headers: { cookie: jar.toString() },
      });

      expect(res.status).toBe(401);
      const lines = res.headers.getSetCookie();
      expect(lines.filter((l) => l.startsWith("__Host-unauth-flow=;"))).toHaveLength(1);
    }
  });

  it("writes the session through a util typed on the h3 event", async () => {
    fake = await createFakeProvider();
    const auth = defineJWESession<SignedIn, "1h", H3Event>({
      key,
      name: "__Host-unauth",
      maxAge: "1h",
    });
    const useAuthSession = (event: H3Event) => auth.use(event);
    const handler = defineSignInHandler(fakeProvider(), {
      key: flowKey,
      redirectUri: REDIRECT_URI,
      fetch: fake.fetch,
      onSuccess: async (event: H3Event, { identity }) => {
        expectTypeOf(event).toEqualTypeOf<H3Event>();
        const session = await useAuthSession(event);
        await session.clear();
        await session.update({ provider: identity.provider, subject: identity.subject });
      },
    });
    expectTypeOf(handler).parameter(0).toEqualTypeOf<H3Event>();
    expectTypeOf(handler).returns.resolves.toEqualTypeOf<Response>();
    app = new H3().get("/auth/fake", handler).get("/me", async (event) => {
      const session = await useAuthSession(event);
      if (!session.id) throw new HTTPError({ status: 401 });
      return session.data;
    });

    const { done, jar } = await signInFlow();
    expect(done.status).toBe(302);
    expect(done.headers.get("location")).toBe("/");
    const cookies = done.headers.getSetCookie();
    expect(cookies.some((line) => /^__Host-unauth-flow=[^;]*;.*Max-Age=0/i.test(line))).toBe(true);
    expect(cookies.some((line) => line.startsWith("__Host-unauth="))).toBe(true);

    const me = await app.request("/me", { headers: { cookie: jar.toString() } });
    expect(await me.json()).toMatchObject({ provider: "fake", subject: "user-1" });
  });

  it("narrows TEvent from one annotation on the event of a hook, the result still inferred", () => {
    const fromSuccess = defineGitHubHandler({
      clientId: "c",
      clientSecret: "s",
      key: flowKey,
      onStart: () => ({ memo: { userId: "u1" } }),
      onSuccess: (event: H3Event, { identity, memo }) => {
        expectTypeOf(identity.profile).toEqualTypeOf<GitHubProfile>();
        expectTypeOf(memo).toEqualTypeOf<{ userId: string } | undefined>();
        return identity.subject;
      },
      onError: (event, error) => {
        expectTypeOf(event).toEqualTypeOf<H3Event>();
        return new Response(null, { status: error.status ?? 500 });
      },
    });
    expectTypeOf(fromSuccess).parameter(0).toEqualTypeOf<H3Event>();
    expectTypeOf(fromSuccess).returns.resolves.toEqualTypeOf<Response | string>();

    const fromStart = defineSignInHandler(fakeProvider(), {
      key: flowKey,
      onStart: (event: H3Event) => (event.req.url ? { memo: { userId: "u1" } } : undefined),
      onSuccess: (event, { identity, memo }) => {
        expectTypeOf(event).toEqualTypeOf<H3Event>();
        expectTypeOf(identity.profile).toEqualTypeOf<Record<string, unknown>>();
        expectTypeOf(memo).toEqualTypeOf<{ userId: string } | undefined>();
      },
      onError: (event) => {
        expectTypeOf(event).toEqualTypeOf<H3Event>();
        return new Response(null, { status: 500 });
      },
    });
    expectTypeOf(fromStart).parameter(0).toEqualTypeOf<H3Event>();

    const plain = defineGitHubHandler({
      clientId: "c",
      clientSecret: "s",
      key: flowKey,
      onStart: (event) => {
        expectTypeOf(event).toEqualTypeOf<WebRequestEvent>();
      },
      onSuccess: (event, { identity }) => {
        expectTypeOf(event).toEqualTypeOf<WebRequestEvent>();
        expectTypeOf(identity.profile).toEqualTypeOf<GitHubProfile>();
      },
    });
    expectTypeOf(plain).parameter(0).toEqualTypeOf<WebRequestEvent>();
  });
});
