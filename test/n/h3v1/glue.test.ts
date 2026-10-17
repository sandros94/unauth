import { beforeAll, describe, expect, it, vi } from "vitest";
import { eventHandler } from "h3";
import { type JWK_oct, generateJWK } from "unjwt/adapters/h3v1";

import { type Provider, isUnauthError, oauth2 } from "../../../src/n/index.ts";
import {
  defineAuthSession,
  defineOAuthEventHandler,
  optionalSession,
  requireSession,
} from "../../../src/n/h3v1/index.ts";
import { cookieJar } from "../../base/_internal/cookies.ts";
import { type H3v1Harness, createH3v1Harness } from "../../base/h3v1/_utils.ts";
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
  return oauth2({
    id: "fake",
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    authorization: `${ISSUER}/authorize`,
    token: `${ISSUER}/token`,
    userinfo: `${ISSUER}/userinfo`,
  });
}

describe("h3 v1 glue", () => {
  let h: H3v1Harness;
  let fake: Awaited<ReturnType<typeof createFakeProvider>>;

  async function setup(overrides: Partial<Parameters<typeof defineOAuthEventHandler>[1]> = {}) {
    fake = await createFakeProvider();
    const auth = defineAuthSession<User>({ key });
    h = createH3v1Harness();
    h.router.get(
      "/auth/fake",
      defineOAuthEventHandler(fakeProvider(), {
        key: flowKey,
        redirectUri: REDIRECT_URI,
        fetch: fake.fetch,
        onSuccess: async (event, result) => {
          const session = await auth.use(event);
          await session.authenticate({ userId: result.identity.subject });
          return { subject: result.identity.subject, redirect: result.redirect ?? null };
        },
        ...overrides,
      }),
    );
    h.router.get(
      "/me",
      eventHandler({
        onRequest: [requireSession(auth)],
        handler: async (event) => (await auth.use(event)).data,
      }),
    );
    return auth;
  }

  async function signInFlow(jar = cookieJar()) {
    const start = await h.request("/auth/fake");
    jar.update(start.headers);
    const back = fake.approve(start.headers.get("location")!);
    const done = await h.request(`${back.pathname}${back.search}`, {
      headers: { cookie: jar.toString() },
    });
    jar.update(done.headers);
    return { start, back, done, jar };
  }

  it("redirects to the provider with a flow cookie on the first leg", async () => {
    await setup();
    const start = await h.request("/auth/fake");

    expect(start.status).toBe(302);
    expect(new URL(start.headers.get("location")!).origin).toBe(ISSUER);
    expect(start.headers.getSetCookie().join("\n")).toMatch(/__Host-unauth-flow=/);
  });

  it("completes the callback leg, clears the flow cookie and signs in", async () => {
    await setup();
    const { done, jar } = await signInFlow();

    expect(done.status).toBe(200);
    expect(await done.json()).toEqual({ subject: "user-1", redirect: null });
    const cookies = done.headers.getSetCookie();
    expect(cookies.some((line) => line.startsWith("__Host-unauth-flow="))).toBe(true);
    expect(cookies.some((line) => line.startsWith("__Host-unauth="))).toBe(true);

    const me = await h.request("/me", { headers: { cookie: jar.toString() } });
    expect(me.status).toBe(200);
    expect(await me.json()).toMatchObject({
      userId: "user-1",
      authenticatedAt: expect.any(Number),
    });
  });

  it("passes onAuthorize's redirect through the flow", async () => {
    await setup({ onAuthorize: () => ({ redirect: "/dashboard" }) });
    const { done } = await signInFlow();

    expect(await done.json()).toEqual({ subject: "user-1", redirect: "/dashboard" });
  });

  it("answers an UnauthError with its status, still clearing the flow cookie", async () => {
    await setup();
    const jar = cookieJar();
    const start = await h.request("/auth/fake");
    jar.update(start.headers);
    const back = fake.approve(start.headers.get("location")!);
    back.searchParams.set("state", "forged");

    const res = await h.request(`${back.pathname}${back.search}`, {
      headers: { cookie: jar.toString() },
    });

    expect(res.status).toBe(401);
    expect(res.headers.getSetCookie().join("\n")).toMatch(/__Host-unauth-flow=/);
  });

  it("hands UnauthErrors to onError when given", async () => {
    const onError = vi.fn((_event: unknown, error: unknown) => ({
      failed: isUnauthError(error) && error.code,
    }));
    await setup({ onError });

    const res = await h.request("/auth/fake?error=access_denied&state=x");

    expect(await res.json()).toEqual({ failed: "ERR_AUTHN_PROVIDER_REFUSED" });
    expect(onError).toHaveBeenCalledOnce();
  });

  it("hides configuration details behind a 500", async () => {
    h = createH3v1Harness();
    h.router.get(
      "/auth/fake",
      defineOAuthEventHandler(fakeProvider(), { key: flowKey, onSuccess: () => "ok" }),
    );

    const res = await h.request("/auth/fake");

    expect(res.status).toBe(500);
    expect(await res.text()).not.toContain("redirectUri");
  });

  it("completes a form_post callback posted to the same route", async () => {
    fake = await createFakeProvider();
    const provider = oauth2({
      id: "fake",
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      authorization: `${ISSUER}/authorize`,
      token: `${ISSUER}/token`,
      userinfo: `${ISSUER}/userinfo`,
      responseMode: "form_post",
    });
    h = createH3v1Harness();
    h.router.use(
      "/auth/fake",
      defineOAuthEventHandler(provider, {
        key: flowKey,
        redirectUri: REDIRECT_URI,
        fetch: fake.fetch,
        onSuccess: (_event, result) => ({ subject: result.identity.subject }),
      }),
      ["get", "post"],
    );
    const jar = cookieJar();
    const start = await h.request("/auth/fake");
    jar.update(start.headers);
    const back = fake.approve(start.headers.get("location")!);

    const done = await h.request("/auth/fake", {
      method: "POST",
      headers: { "cookie": jar.toString(), "content-type": "application/x-www-form-urlencoded" },
      body: back.searchParams.toString(),
    });

    expect(done.status).toBe(200);
    expect(await done.json()).toEqual({ subject: "user-1" });
  });

  it("requireSession answers 401 without an authenticated session", async () => {
    await setup();
    expect((await h.request("/me")).status).toBe(401);
  });

  it("optionalSession calls onAuthenticated only for an authenticated session", async () => {
    const auth = await setup();
    const onAuthenticated = vi.fn();
    h.router.get(
      "/feed",
      eventHandler({
        onRequest: [optionalSession(auth, { onAuthenticated })],
        handler: () => "feed",
      }),
    );

    expect((await h.request("/feed")).status).toBe(200);
    expect(onAuthenticated).not.toHaveBeenCalled();

    const { jar } = await signInFlow();
    await h.request("/feed", { headers: { cookie: jar.toString() } });
    expect(onAuthenticated).toHaveBeenCalledOnce();
    expect(onAuthenticated.mock.calls[0]![0].session.data.userId).toBe("user-1");
  });
});
