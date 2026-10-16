import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from "vitest";
import { H3, HTTPError } from "h3";

import {
  type JWK_oct,
  defineSession,
  generateJWK,
  optionalSession,
  requireSession,
} from "../../../src/base/h3v2/index.ts";

import { cookieJar } from "../_internal/cookies.ts";

let key: JWK_oct<"A256GCMKW">;

beforeAll(async () => {
  key = await generateJWK("A256GCMKW");
});

afterEach(() => {
  vi.useRealTimers();
});

describe("defineSession", () => {
  let app: H3;

  beforeEach(() => {
    app = new H3();
  });

  it("returns empty session initially", async () => {
    const useSession = defineSession({
      key,
      maxAge: "1h",
      cookie: { secure: false },
    });

    app.get("/", async (event) => {
      const session = await useSession(event);
      return { id: session.id ?? null, data: session.data };
    });

    const res = await app.request("/");
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

    app.post("/login", async (event) => {
      const session = await useSession(event);
      await session.update({ userId: "u1", role: "admin" });
      return { ok: true };
    });
    app.get("/me", async (event) => {
      const session = await useSession(event);
      return { id: session.id ?? null, data: session.data };
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    const meRes = await app.request("/me", {
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

    app.post("/login", async (event) => {
      const session = await useSession(event);
      await session.update({ userId: "u1" });
      return { ok: true };
    });
    app.post("/logout", async (event) => {
      const session = await useSession(event);
      await session.clear();
      return { ok: true };
    });
    app.get("/me", async (event) => {
      const session = await useSession(event);
      return { id: session.id ?? null };
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    const authedRes = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    expect((await authedRes.json()).id).toBeTypeOf("string");

    const logoutRes = await app.request("/logout", {
      method: "POST",
      headers: { Cookie: jar.toString() },
    });
    jar.update(logoutRes.headers);

    const clearedRes = await app.request("/me", {
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

    app.post("/login", async (event) => {
      const session = await useSession(event);
      await session.update({ userId: "u1" });
      return { ok: true };
    });
    app.get("/me", async (event) => {
      const session = await useSession(event);
      return { id: session.id ?? null, data: session.data };
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    // 30 minutes left: more than the 15 minute window, nothing is reissued.
    vi.setSystemTime(new Date("2026-01-01T00:30:00Z"));
    const earlyRes = await app.request("/me", { headers: { Cookie: jar.toString() } });
    const idBefore = (await earlyRes.json()).id;
    expect(idBefore).toBeTypeOf("string");
    expect(earlyRes.headers.getSetCookie()).toEqual([]);
    expect(onUpdate).toHaveBeenCalledTimes(1);

    // 14 minutes left: inside the window, the session rolls.
    vi.setSystemTime(new Date("2026-01-01T00:46:00Z"));
    const rollRes = await app.request("/me", { headers: { Cookie: jar.toString() } });
    jar.update(rollRes.headers);
    expect(rollRes.headers.getSetCookie()).not.toEqual([]);
    expect(onUpdate).toHaveBeenCalledTimes(2);
    expect(onUpdate.mock.calls[1]![0].trigger).toBe("rolling");

    const afterRes = await app.request("/me", { headers: { Cookie: jar.toString() } });
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

    app.post("/login", async (event) => {
      const session = await useSession(event);
      await session.update({ userId: "u1" });
      return { ok: true };
    });
    app.get("/me", async (event) => {
      const session = await useSession(event);
      return { id: session.id ?? null, data: session.data };
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);
    const idBefore = (
      await (await app.request("/me", { headers: { Cookie: jar.toString() } })).json()
    ).id;

    vi.setSystemTime(new Date("2026-01-01T00:31:00Z"));
    const rollRes = await app.request("/me", { headers: { Cookie: jar.toString() } });
    jar.update(rollRes.headers);

    const afterBody = await (
      await app.request("/me", { headers: { Cookie: jar.toString() } })
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

    app.post("/login", async (event) => {
      const session = await useSession(event);
      await session.update({ userId: "u1" });
      return { ok: true };
    });
    app.get("/me", async (event) => {
      const session = await useSession(event);
      return { id: session.id ?? null, data: session.data };
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    const first = await app.request("/me", { headers: { Cookie: jar.toString() } });
    jar.update(first.headers);
    const second = await app.request("/me", { headers: { Cookie: jar.toString() } });

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

    app.post("/login", async (event) => {
      const session = await useSession(event);
      await session.update({ userId: "u1" });
      return { ok: true };
    });
    app.get("/me", async (event) => {
      const session = await useSession(event);
      return { id: session.id ?? null, data: session.data };
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    vi.setSystemTime(new Date("2026-01-01T00:59:00Z"));
    const res = await app.request("/me", { headers: { Cookie: jar.toString() } });

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

    app.post("/login", async (event) => {
      const session = await useSession(event);
      await session.update({ userId: "u1", role: "user" });
      return { ok: true };
    });
    app.get("/me", async (event) => {
      const session = await useSession(event);
      return { id: session.id ?? null, data: session.data };
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    const firstRes = await app.request("/me", { headers: { Cookie: jar.toString() } });
    jar.update(firstRes.headers);
    expect((await firstRes.json()).data.role).toBe("superadmin");

    const secondRes = await app.request("/me", { headers: { Cookie: jar.toString() } });
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

    app.post("/login", async (event) => {
      const session = await useSession(event);
      await session.update({ userId: "u1", banned: true });
      return { ok: true };
    });
    app.get("/me", async (event) => {
      const session = await useSession(event);
      return { id: session.id ?? null };
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    const meRes = await app.request("/me", { headers: { Cookie: jar.toString() } });
    jar.update(meRes.headers);

    expect(clearSpy).toHaveBeenCalledTimes(1);
    expect((await meRes.json()).id).toBeNull();

    const clearedRes = await app.request("/me", { headers: { Cookie: jar.toString() } });
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

    app.post("/login", async (event) => {
      const session = await useSession(event);
      await session.update({ userId: "u1" });
      return { ok: true };
    });
    app.get("/me", async (event) => {
      const session = await useSession(event);
      return { id: session.id ?? null };
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    // Advance well past maxAge
    vi.setSystemTime(new Date("2026-01-01T02:00:00Z"));

    const res = await app.request("/me", { headers: { Cookie: jar.toString() } });
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

    app.post("/login", async (event) => {
      const session = await useSession(event);
      await session.update({ userId: "u1" });
      return { ok: true };
    });
    app.get("/me", async (event) => {
      const session = await useSession(event);
      return { data: session.data };
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);
    expect(onRead).not.toHaveBeenCalled();

    await app.request("/me", { headers: { Cookie: jar.toString() } });

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

    app.post("/login", async (event) => {
      const session = await useSession(event);
      await session.update({ userId: "u1" });
      return { ok: true };
    });
    app.get("/me", async (event) => {
      const session = await useSession(event);
      return { id: session.id ?? null };
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    const res = await app.request("/me", { headers: { Cookie: jar.toString() } });
    expect((await res.json()).id).toBe("fixed-id");
  });
});

describe("requireSession", () => {
  let app: H3;

  beforeEach(() => {
    app = new H3();
  });

  it("passes when session is authenticated", async () => {
    const useSession = defineSession({
      key,
      maxAge: "1h",
      cookie: { secure: false },
    });

    app.post("/login", async (event) => {
      const session = await useSession(event);
      await session.update({ userId: "u1" });
      return { ok: true };
    });
    app.get(
      "/me",
      async (event) => {
        const session = await useSession(event);
        return { userId: session.data.userId };
      },
      { middleware: [requireSession(useSession)] },
    );

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    const meRes = await app.request("/me", {
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

    app.get("/me", () => ({ ok: true }), { middleware: [requireSession(useSession)] });

    const res = await app.request("/me");
    expect(res.status).toBe(401);
  });

  it("calls onAuthenticated hook", async () => {
    const onAuthenticated = vi.fn();
    const useSession = defineSession({
      key,
      maxAge: "1h",
      cookie: { secure: false },
    });

    app.post("/login", async (event) => {
      const session = await useSession(event);
      await session.update({ userId: "u1" });
      return { ok: true };
    });
    app.get(
      "/me",
      async (event) => {
        const session = await useSession(event);
        return { userId: session.data.userId };
      },
      { middleware: [requireSession(useSession, { onAuthenticated })] },
    );

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    await app.request("/me", {
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

    app.post("/login", async (event) => {
      const session = await useSession(event);
      await session.update({ userId: "u1", role: "user" });
      return { ok: true };
    });
    app.get("/admin", () => ({ ok: true }), {
      middleware: [
        requireSession(useSession, {
          async onAuthenticated({ session }) {
            if (session.data.role !== "admin") {
              throw new HTTPError("Forbidden", { status: 403 });
            }
          },
        }),
      ],
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    const res = await app.request("/admin", {
      headers: { Cookie: jar.toString() },
    });
    expect(res.status).toBe(403);
  });
});

describe("optionalSession", () => {
  let app: H3;

  beforeEach(() => {
    app = new H3();
  });

  it("passes when session is authenticated", async () => {
    const useSession = defineSession({
      key,
      maxAge: "1h",
      cookie: { secure: false },
    });

    app.post("/login", async (event) => {
      const session = await useSession(event);
      await session.update({ userId: "u1" });
      return { ok: true };
    });
    app.get(
      "/feed",
      async (event) => {
        const session = await useSession(event);
        return {
          authenticated: !!session.id,
          userId: session.data.userId ?? null,
        };
      },
      { middleware: [optionalSession(useSession)] },
    );

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    const feedRes = await app.request("/feed", {
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

    app.get(
      "/feed",
      async (event) => {
        const session = await useSession(event);
        return {
          authenticated: !!session.id,
          userId: session.data.userId ?? null,
        };
      },
      { middleware: [optionalSession(useSession)] },
    );

    const res = await app.request("/feed");
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

    app.get("/feed", () => ({ ok: true }), {
      middleware: [optionalSession(useSession, { onAuthenticated })],
    });

    // Unauthenticated request
    await app.request("/feed");
    expect(onAuthenticated).not.toHaveBeenCalled();
  });
});
