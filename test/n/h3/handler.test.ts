import { beforeAll, describe, expect, it, vi } from "vitest";
import { H3, type H3Event } from "h3";
import { type JWK_oct, generateJWK } from "unjwt/session";

import {
  type Provider,
  defineAuthSession,
  defineSignInHandler,
  defineOAuth2Provider,
  defineSessionGuard,
} from "../../../src/n/index.ts";
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
    const auth = defineAuthSession<User, H3Event>({ key });
    app = new H3();
    app.get(
      "/auth/fake",
      defineSignInHandler(fakeProvider(), {
        key: flowKey,
        redirectUri: REDIRECT_URI,
        fetch: fake.fetch,
        onSuccess: async (event: H3Event, result) => {
          const session = await auth.use(event);
          await session.authenticate({ userId: result.identity.subject });
          return { subject: result.identity.subject, redirect: result.redirect ?? null };
        },
      }),
    );
    app.get("/me", async (event) => (await auth.require(event)).data, {
      middleware: [defineSessionGuard(auth)],
    });
    return auth;
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
    expect(await me.json()).toMatchObject({
      userId: "user-1",
      authenticatedAt: expect.any(Number),
    });
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

  it("defineSessionGuard answers 401 without an authenticated session", async () => {
    await setup();
    expect((await app.request("/me")).status).toBe(401);
  });

  it("defineSessionGuard runs onAuthenticated with the h3 event as context", async () => {
    const auth = await setup();
    const onAuthenticated = vi.fn((_args: { context: H3Event }) => undefined);
    app.get("/feed", () => "feed", {
      middleware: [defineSessionGuard(auth, { onAuthenticated })],
    });

    expect((await app.request("/feed")).status).toBe(401);
    expect(onAuthenticated).not.toHaveBeenCalled();

    const { jar } = await signInFlow();
    expect((await app.request("/feed", { headers: { cookie: jar.toString() } })).status).toBe(200);
    expect(onAuthenticated).toHaveBeenCalledOnce();
    expect(onAuthenticated.mock.calls[0]![0].context.req).toBeInstanceOf(Request);
  });

  it("hooks receive the h3 event as context", async () => {
    const isRevoked = vi.fn((_args: { context: H3Event }) => false);
    const auth = defineAuthSession<User, H3Event>({ key, hooks: { isRevoked } });
    const signed = new H3();
    signed.get("/in", async (event) => {
      await (await auth.use(event)).authenticate({ userId: "u1" });
      return "in";
    });
    signed.get("/read", async (event) => (await auth.use(event)).data.userId ?? null);
    const jar = cookieJar();
    jar.update((await signed.request("/in")).headers);

    const read = await signed.request("/read", { headers: { cookie: jar.toString() } });
    expect(await read.text()).toBe("u1");
    expect(isRevoked.mock.calls[0]![0].context.req).toBeInstanceOf(Request);
  });
});
