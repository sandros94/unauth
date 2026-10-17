import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from "vitest";
import { eventHandler, createError } from "h3";

import {
  type JWK_oct,
  defineSession,
  generateJWK,
  optionalSession,
  requireSession,
} from "../../../src/base/h3v1/index.ts";

import { cookieJar } from "../_internal/cookies.ts";
import { createH3v1Harness, type H3v1Harness } from "./_utils.ts";

let key: JWK_oct<"A256GCMKW">;

beforeAll(async () => {
  key = await generateJWK("A256GCMKW");
});

afterEach(() => {
  vi.useRealTimers();
});

describe("defineSession (h3v1)", () => {
  let h: H3v1Harness;

  beforeEach(() => {
    h = createH3v1Harness();
  });

  it("returns empty session initially", async () => {
    const useSession = defineSession({
      key,
      maxAge: "1h",
      cookie: { secure: false },
    });

    h.router.get(
      "/",
      eventHandler(async (event) => {
        const session = await useSession(event);
        return { id: session.id ?? null, data: session.data };
      }),
    );

    const res = await h.request("/");
    const body = await res.json();
    expect(body.id).toBeNull();
    expect(body.data).toEqual({});
  });

  it("updates and reads back session data", async () => {
    const useSession = defineSession({
      key,
      maxAge: "1h",
      cookie: { secure: false },
    });

    h.router.post(
      "/login",
      eventHandler(async (event) => {
        const session = await useSession(event);
        await session.update({ userId: "u1", role: "admin" });
        return { ok: true };
      }),
    );
    h.router.get(
      "/me",
      eventHandler(async (event) => {
        const session = await useSession(event);
        return { id: session.id ?? null, data: session.data };
      }),
    );

    const jar = cookieJar();

    const loginRes = await h.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    const meRes = await h.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    const body = await meRes.json();

    expect(body.id).toBeTypeOf("string");
    expect(body.data.userId).toBe("u1");
    expect(body.data.role).toBe("admin");
  });

  it("clears session", async () => {
    const useSession = defineSession({
      key,
      maxAge: "1h",
      cookie: { secure: false },
    });

    h.router.post(
      "/login",
      eventHandler(async (event) => {
        const session = await useSession(event);
        await session.update({ userId: "u1" });
        return { ok: true };
      }),
    );
    h.router.post(
      "/logout",
      eventHandler(async (event) => {
        const session = await useSession(event);
        await session.clear();
        return { ok: true };
      }),
    );
    h.router.get(
      "/me",
      eventHandler(async (event) => {
        const session = await useSession(event);
        return { id: session.id ?? null };
      }),
    );

    const jar = cookieJar();

    const loginRes = await h.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    const authedRes = await h.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    expect((await authedRes.json()).id).toBeTypeOf("string");

    const logoutRes = await h.request("/logout", {
      method: "POST",
      headers: { Cookie: jar.toString() },
    });
    jar.update(logoutRes.headers);

    const clearedRes = await h.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    expect((await clearedRes.json()).id).toBeNull();
  });

  it("rolls the session by default once less than a quarter of maxAge remains", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const onUpdate = vi.fn();
    const useSession = defineSession({
      key,
      maxAge: "1h",
      cookie: { secure: false },
      hooks: { onUpdate },
    });

    h.router.post(
      "/login",
      eventHandler(async (event) => {
        const session = await useSession(event);
        await session.update({ userId: "u1" });
        return { ok: true };
      }),
    );
    h.router.get(
      "/me",
      eventHandler(async (event) => {
        const session = await useSession(event);
        return { id: session.id ?? null, data: session.data };
      }),
    );

    const jar = cookieJar();

    const loginRes = await h.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    // 30 minutes left: more than the 15 minute window, nothing is reissued.
    vi.setSystemTime(new Date("2026-01-01T00:30:00Z"));
    const earlyRes = await h.request("/me", { headers: { Cookie: jar.toString() } });
    const idBefore = (await earlyRes.json()).id;
    expect(idBefore).toBeTypeOf("string");
    expect(earlyRes.headers.getSetCookie()).toEqual([]);
    expect(onUpdate).toHaveBeenCalledTimes(1);

    // 14 minutes left: inside the window, the session rolls.
    vi.setSystemTime(new Date("2026-01-01T00:46:00Z"));
    const rollRes = await h.request("/me", { headers: { Cookie: jar.toString() } });
    jar.update(rollRes.headers);
    expect(rollRes.headers.getSetCookie()).not.toEqual([]);
    expect(onUpdate).toHaveBeenCalledTimes(2);
    expect(onUpdate.mock.calls[1]![0].trigger).toBe("rolling");

    const afterRes = await h.request("/me", { headers: { Cookie: jar.toString() } });
    const afterBody = await afterRes.json();
    expect(afterBody.id).toBeTypeOf("string");
    expect(afterBody.id).not.toBe(idBefore);
    expect(afterBody.data.userId).toBe("u1");
  });

  it("rolls once less than a custom duration remains", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const onUpdate = vi.fn();
    const useSession = defineSession({
      key,
      maxAge: "1h",
      rolling: "30m",
      cookie: { secure: false },
      hooks: { onUpdate },
    });

    h.router.post(
      "/login",
      eventHandler(async (event) => {
        const session = await useSession(event);
        await session.update({ userId: "u1" });
        return { ok: true };
      }),
    );
    h.router.get(
      "/me",
      eventHandler(async (event) => {
        const session = await useSession(event);
        return { id: session.id ?? null, data: session.data };
      }),
    );

    const jar = cookieJar();

    const loginRes = await h.request("/login", { method: "POST" });
    jar.update(loginRes.headers);
    const idBefore = (
      await (await h.request("/me", { headers: { Cookie: jar.toString() } })).json()
    ).id;

    vi.setSystemTime(new Date("2026-01-01T00:31:00Z"));
    const rollRes = await h.request("/me", { headers: { Cookie: jar.toString() } });
    jar.update(rollRes.headers);

    const afterBody = await (
      await h.request("/me", { headers: { Cookie: jar.toString() } })
    ).json();
    expect(afterBody.id).not.toBe(idBefore);
    expect(onUpdate).toHaveBeenCalledTimes(2);
  });

  it("rolls on every read with rolling: true", async () => {
    const onUpdate = vi.fn();
    const useSession = defineSession({
      key,
      maxAge: "1h",
      rolling: true,
      cookie: { secure: false },
      hooks: { onUpdate },
    });

    h.router.post(
      "/login",
      eventHandler(async (event) => {
        const session = await useSession(event);
        await session.update({ userId: "u1" });
        return { ok: true };
      }),
    );
    h.router.get(
      "/me",
      eventHandler(async (event) => {
        const session = await useSession(event);
        return { id: session.id ?? null, data: session.data };
      }),
    );

    const jar = cookieJar();

    const loginRes = await h.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    const first = await h.request("/me", { headers: { Cookie: jar.toString() } });
    jar.update(first.headers);
    const second = await h.request("/me", { headers: { Cookie: jar.toString() } });

    expect((await first.json()).id).not.toBe((await second.json()).id);
    expect(onUpdate).toHaveBeenCalledTimes(3);
  });

  it("never rolls with rolling: false", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const onUpdate = vi.fn();
    const useSession = defineSession({
      key,
      maxAge: "1h",
      rolling: false,
      cookie: { secure: false },
      hooks: { onUpdate },
    });

    h.router.post(
      "/login",
      eventHandler(async (event) => {
        const session = await useSession(event);
        await session.update({ userId: "u1" });
        return { ok: true };
      }),
    );
    h.router.get(
      "/me",
      eventHandler(async (event) => {
        const session = await useSession(event);
        return { id: session.id ?? null, data: session.data };
      }),
    );

    const jar = cookieJar();

    const loginRes = await h.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    vi.setSystemTime(new Date("2026-01-01T00:59:00Z"));
    const res = await h.request("/me", { headers: { Cookie: jar.toString() } });

    expect(res.headers.getSetCookie()).toEqual([]);
    expect((await res.json()).data.userId).toBe("u1");
    expect(onUpdate).toHaveBeenCalledTimes(1);
  });

  it("lets onRead update the session with new data", async () => {
    const useSession = defineSession({
      key,
      maxAge: "1h",
      cookie: { secure: false },
      hooks: {
        async onRead({ session }) {
          if (session.data.role !== "superadmin") await session.update({ role: "superadmin" });
        },
      },
    });

    h.router.post(
      "/login",
      eventHandler(async (event) => {
        const session = await useSession(event);
        await session.update({ userId: "u1", role: "user" });
        return { ok: true };
      }),
    );
    h.router.get(
      "/me",
      eventHandler(async (event) => {
        const session = await useSession(event);
        return { id: session.id ?? null, data: session.data };
      }),
    );

    const jar = cookieJar();

    const loginRes = await h.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    const firstRes = await h.request("/me", { headers: { Cookie: jar.toString() } });
    jar.update(firstRes.headers);
    expect((await firstRes.json()).data.role).toBe("superadmin");

    const secondRes = await h.request("/me", { headers: { Cookie: jar.toString() } });
    expect((await secondRes.json()).data).toEqual({ userId: "u1", role: "superadmin" });
  });

  it("lets onRead clear the session", async () => {
    const clearSpy = vi.fn();
    const useSession = defineSession({
      key,
      maxAge: "1h",
      cookie: { secure: false },
      hooks: {
        async onRead({ session }) {
          if (session.data.banned) {
            clearSpy();
            await session.clear();
          }
        },
      },
    });

    h.router.post(
      "/login",
      eventHandler(async (event) => {
        const session = await useSession(event);
        await session.update({ userId: "u1", banned: true });
        return { ok: true };
      }),
    );
    h.router.get(
      "/me",
      eventHandler(async (event) => {
        const session = await useSession(event);
        return { id: session.id ?? null };
      }),
    );

    const jar = cookieJar();

    const loginRes = await h.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    const meRes = await h.request("/me", { headers: { Cookie: jar.toString() } });
    jar.update(meRes.headers);

    expect(clearSpy).toHaveBeenCalledTimes(1);
    expect((await meRes.json()).id).toBeNull();

    const clearedRes = await h.request("/me", { headers: { Cookie: jar.toString() } });
    expect((await clearedRes.json()).id).toBeNull();
  });

  it("returns empty session after expiry", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const useSession = defineSession({
      key,
      maxAge: "1h",
      cookie: { secure: false },
    });

    h.router.post(
      "/login",
      eventHandler(async (event) => {
        const session = await useSession(event);
        await session.update({ userId: "u1" });
        return { ok: true };
      }),
    );
    h.router.get(
      "/me",
      eventHandler(async (event) => {
        const session = await useSession(event);
        return { id: session.id ?? null };
      }),
    );

    const jar = cookieJar();

    const loginRes = await h.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    // Advance well past maxAge
    vi.setSystemTime(new Date("2026-01-01T02:00:00Z"));

    const res = await h.request("/me", { headers: { Cookie: jar.toString() } });
    expect((await res.json()).id).toBeNull();
  });

  it("calls onRead once per request with the live session manager", async () => {
    const onRead = vi.fn();
    const useSession = defineSession({
      key,
      maxAge: "1h",
      cookie: { secure: false },
      hooks: { onRead },
    });

    h.router.post(
      "/login",
      eventHandler(async (event) => {
        const session = await useSession(event);
        await session.update({ userId: "u1" });
        return { ok: true };
      }),
    );
    h.router.get(
      "/me",
      eventHandler(async (event) => {
        const session = await useSession(event);
        return { data: session.data };
      }),
    );

    const jar = cookieJar();

    const loginRes = await h.request("/login", { method: "POST" });
    jar.update(loginRes.headers);
    expect(onRead).not.toHaveBeenCalled();

    await h.request("/me", { headers: { Cookie: jar.toString() } });

    expect(onRead).toHaveBeenCalledTimes(1);
    const { session } = onRead.mock.calls[0]![0];
    expect(session.id).toBeTypeOf("string");
    expect(session.update).toBeTypeOf("function");
    expect(session.clear).toBeTypeOf("function");
  });

  it("forwards the remaining unjwt options", async () => {
    const useSession = defineSession({
      key,
      maxAge: "1h",
      cookie: { secure: false },
      generateId: () => "fixed-id",
    });

    h.router.post(
      "/login",
      eventHandler(async (event) => {
        const session = await useSession(event);
        await session.update({ userId: "u1" });
        return { ok: true };
      }),
    );
    h.router.get(
      "/me",
      eventHandler(async (event) => {
        const session = await useSession(event);
        return { id: session.id ?? null };
      }),
    );

    const jar = cookieJar();

    const loginRes = await h.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    const res = await h.request("/me", { headers: { Cookie: jar.toString() } });
    expect((await res.json()).id).toBe("fixed-id");
  });
});

describe("requireSession (h3v1)", () => {
  let h: H3v1Harness;

  beforeEach(() => {
    h = createH3v1Harness();
  });

  it("passes when session is authenticated", async () => {
    const useSession = defineSession({
      key,
      maxAge: "1h",
      cookie: { secure: false },
    });

    h.router.post(
      "/login",
      eventHandler(async (event) => {
        const session = await useSession(event);
        await session.update({ userId: "u1" });
        return { ok: true };
      }),
    );
    h.router.get(
      "/me",
      eventHandler({
        onRequest: requireSession(useSession),
        handler: async (event) => {
          const session = await useSession(event);
          return { userId: session.data.userId };
        },
      }),
    );

    const jar = cookieJar();

    const loginRes = await h.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    const meRes = await h.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    expect(meRes.status).toBe(200);
    expect((await meRes.json()).userId).toBe("u1");
  });

  it("throws 401 when no session", async () => {
    const useSession = defineSession({
      key,
      maxAge: "1h",
      cookie: { secure: false },
    });

    h.router.get(
      "/me",
      eventHandler({
        onRequest: requireSession(useSession),
        handler: () => ({ ok: true }),
      }),
    );

    const res = await h.request("/me");
    expect(res.status).toBe(401);
  });

  it("calls onAuthenticated hook", async () => {
    const onAuthenticated = vi.fn();
    const useSession = defineSession({
      key,
      maxAge: "1h",
      cookie: { secure: false },
    });

    h.router.post(
      "/login",
      eventHandler(async (event) => {
        const session = await useSession(event);
        await session.update({ userId: "u1" });
        return { ok: true };
      }),
    );
    h.router.get(
      "/me",
      eventHandler({
        onRequest: requireSession(useSession, { onAuthenticated }),
        handler: async (event) => {
          const session = await useSession(event);
          return { userId: session.data.userId };
        },
      }),
    );

    const jar = cookieJar();

    const loginRes = await h.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    await h.request("/me", {
      headers: { Cookie: jar.toString() },
    });

    expect(onAuthenticated).toHaveBeenCalledTimes(1);
    expect(onAuthenticated.mock.calls[0]![0].session.id).toBeTypeOf("string");
  });

  it("propagates onAuthenticated errors", async () => {
    const useSession = defineSession({
      key,
      maxAge: "1h",
      cookie: { secure: false },
    });

    h.router.post(
      "/login",
      eventHandler(async (event) => {
        const session = await useSession(event);
        await session.update({ userId: "u1", role: "user" });
        return { ok: true };
      }),
    );
    h.router.get(
      "/admin",
      eventHandler({
        onRequest: requireSession(useSession, {
          async onAuthenticated({ session }) {
            if (session.data.role !== "admin") {
              throw createError({ statusCode: 403, statusMessage: "Forbidden" });
            }
          },
        }),
        handler: () => ({ ok: true }),
      }),
    );

    const jar = cookieJar();

    const loginRes = await h.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    const res = await h.request("/admin", {
      headers: { Cookie: jar.toString() },
    });
    expect(res.status).toBe(403);
  });
});

describe("optionalSession (h3v1)", () => {
  let h: H3v1Harness;

  beforeEach(() => {
    h = createH3v1Harness();
  });

  it("passes when session is authenticated", async () => {
    const useSession = defineSession({
      key,
      maxAge: "1h",
      cookie: { secure: false },
    });

    h.router.post(
      "/login",
      eventHandler(async (event) => {
        const session = await useSession(event);
        await session.update({ userId: "u1" });
        return { ok: true };
      }),
    );
    h.router.get(
      "/feed",
      eventHandler({
        onRequest: optionalSession(useSession),
        handler: async (event) => {
          const session = await useSession(event);
          return {
            authenticated: !!session.id,
            userId: session.data.userId ?? null,
          };
        },
      }),
    );

    const jar = cookieJar();

    const loginRes = await h.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    const feedRes = await h.request("/feed", {
      headers: { Cookie: jar.toString() },
    });
    const body = await feedRes.json();
    expect(feedRes.status).toBe(200);
    expect(body.authenticated).toBe(true);
    expect(body.userId).toBe("u1");
  });

  it("passes when no session (unauthenticated)", async () => {
    const useSession = defineSession({
      key,
      maxAge: "1h",
      cookie: { secure: false },
    });

    h.router.get(
      "/feed",
      eventHandler({
        onRequest: optionalSession(useSession),
        handler: async (event) => {
          const session = await useSession(event);
          return {
            authenticated: !!session.id,
            userId: session.data.userId ?? null,
          };
        },
      }),
    );

    const res = await h.request("/feed");
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.authenticated).toBe(false);
    expect(body.userId).toBeNull();
  });

  it("calls onAuthenticated only when authenticated", async () => {
    const onAuthenticated = vi.fn();
    const useSession = defineSession({
      key,
      maxAge: "1h",
      cookie: { secure: false },
    });

    h.router.get(
      "/feed",
      eventHandler({
        onRequest: optionalSession(useSession, { onAuthenticated }),
        handler: () => ({ ok: true }),
      }),
    );

    // Unauthenticated request
    await h.request("/feed");
    expect(onAuthenticated).not.toHaveBeenCalled();
  });
});

describe("defineSession — read-only compat events (h3v1)", () => {
  let h: H3v1Harness;

  beforeEach(() => {
    h = createH3v1Harness();
  });

  /** The shape crossws hands a WebSocket `upgrade` hook. */
  const upgradeEvent = (cookie: string) => ({
    url: "http://localhost/_ws",
    headers: new Headers({ cookie }),
    context: {},
  });

  async function login(useSession: ReturnType<typeof defineSession>) {
    h.router.post(
      "/login",
      eventHandler(async (event) => {
        const session = await useSession(event);
        await session.update({ userId: "u1", role: "user" });
        return { ok: true };
      }),
    );
    const jar = cookieJar();
    jar.update((await h.request("/login", { method: "POST" })).headers);
    return jar;
  }

  it("resolves a session from an upgrade-shaped event", async () => {
    const useSession = defineSession({ key, maxAge: "1h", cookie: { secure: false } });
    const jar = await login(useSession);

    const session = await useSession(upgradeEvent(jar.toString()));

    expect(session.id).toBeTruthy();
    expect(session.data).toMatchObject({ userId: "u1", role: "user" });
  });

  it("also accepts the { request: { headers } } shape", async () => {
    const useSession = defineSession({ key, maxAge: "1h", cookie: { secure: false } });
    const jar = await login(useSession);

    const session = await useSession({
      request: { headers: new Headers({ cookie: jar.toString() }) },
      context: {},
    });

    expect(session.data).toMatchObject({ userId: "u1" });
  });

  it("resolves nothing when the upgrade carries no cookie", async () => {
    const useSession = defineSession({ key, maxAge: "1h", cookie: { secure: false } });

    const session = await useSession(upgradeEvent(""));

    expect(session.id).toBeUndefined();
    expect(session.data).toEqual({});
  });

  it("does not roll through a read-only event, and reports it as a read", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const onRead = vi.fn();
    const onUpdate = vi.fn();
    const onError = vi.fn();
    const useSession = defineSession({
      key,
      maxAge: "1h",
      rolling: "30m",
      cookie: { secure: false },
      hooks: { onRead, onUpdate, onError },
    });
    const jar = await login(useSession);

    // Inside the rolling window — an H3Event here would reissue the session.
    vi.setSystemTime(new Date("2026-01-01T00:31:00Z"));
    const session = await useSession(upgradeEvent(jar.toString()));

    expect(session.data).toMatchObject({ userId: "u1" });
    expect(onRead).toHaveBeenCalledTimes(1);
    expect(onUpdate).toHaveBeenCalledTimes(1); // the login only
    expect(onError).not.toHaveBeenCalled();
  });

  it("still rolls on a real H3Event", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const onUpdate = vi.fn();
    const useSession = defineSession({
      key,
      maxAge: "1h",
      rolling: "30m",
      cookie: { secure: false },
      hooks: { onUpdate },
    });
    const jar = await login(useSession);

    h.router.get(
      "/me",
      eventHandler(async (event) => {
        const session = await useSession(event);
        return { data: session.data };
      }),
    );

    vi.setSystemTime(new Date("2026-01-01T00:31:00Z"));
    jar.update((await h.request("/me", { headers: { Cookie: jar.toString() } })).headers);

    expect(onUpdate).toHaveBeenCalledTimes(2);
    expect(onUpdate.mock.calls[1]![0].trigger).toBe("rolling");
  });

  it("refuses an update through a compat event, and clears without writing", async () => {
    const useSession = defineSession({ key, maxAge: "1h", cookie: { secure: false } });
    const jar = await login(useSession);

    const session = await useSession(upgradeEvent(jar.toString()));

    await expect(session.update({ role: "superadmin" })).rejects.toThrow(/read-only/i);
    await session.clear();
    expect(session.id).toBeUndefined();
  });
});
