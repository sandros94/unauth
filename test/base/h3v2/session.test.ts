import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from "vitest";
import { H3, HTTPError } from "h3v2";

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
    console.log("test", body);
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

  it("auto-refreshes with sliding window when no onRefresh hook", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const useSession = defineSession({
      key,
      maxAge: "1h",
      refreshAfter: 0.5,
      cookie: { secure: false },
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

    // Read before threshold — capture session id
    const beforeRes = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    const idBefore = (await beforeRes.json()).id;
    expect(idBefore).toBeTypeOf("string");

    // Advance past 50% of 1h
    vi.setSystemTime(new Date("2026-01-01T00:31:00Z"));

    // This request triggers auto-refresh (new cookie set)
    const refreshRes = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    jar.update(refreshRes.headers);

    // Reset time to avoid double-refresh
    vi.setSystemTime(new Date("2026-01-01T00:31:01Z"));

    // Next request uses the refreshed cookie — should have new id
    const afterRes = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    const afterBody = await afterRes.json();
    expect(afterBody.id).toBeTypeOf("string");
    expect(afterBody.id).not.toBe(idBefore);
    expect(afterBody.data.userId).toBe("u1");
  });

  it("calls onRefresh and refreshes with new data", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const useSession = defineSession({
      key,
      maxAge: "1h",
      refreshAfter: 0.5,
      cookie: { secure: false },
      hooks: {
        async onRefresh({ refresh }) {
          await refresh({ userId: "u1", role: "superadmin" });
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

    vi.setSystemTime(new Date("2026-01-01T00:31:00Z"));

    const refreshRes = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    jar.update(refreshRes.headers);

    vi.setSystemTime(new Date("2026-01-01T00:31:01Z"));

    const afterRes = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    const body = await afterRes.json();
    expect(body.data.role).toBe("superadmin");
  });

  it("skips refresh when refresh() is not called in onRefresh", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const onRefreshSpy = vi.fn();
    const onUpdate = vi.fn();
    const useSession = defineSession({
      key,
      maxAge: "1h",
      refreshAfter: 0.5,
      cookie: { secure: false },
      hooks: {
        onRefresh: onRefreshSpy,
        onUpdate,
      },
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

    vi.setSystemTime(new Date("2026-01-01T00:31:00Z"));

    const res = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    const body = await res.json();

    expect(onRefreshSpy).toHaveBeenCalledTimes(1);
    // onUpdate only from login, NOT from refresh
    expect(onUpdate).toHaveBeenCalledTimes(1);
    expect(body.data.userId).toBe("u1");
  });

  it("clears session from onRefresh via clear()", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const useSession = defineSession({
      key,
      maxAge: "1h",
      refreshAfter: 0.5,
      cookie: { secure: false },
      hooks: {
        async onRefresh({ clear }) {
          await clear();
        },
      },
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

    vi.setSystemTime(new Date("2026-01-01T00:31:00Z"));

    const refreshRes = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    jar.update(refreshRes.headers);

    const clearedRes = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    expect((await clearedRes.json()).id).toBeNull();
  });

  it("clears session from onRead via clear()", async () => {
    const clearSpy = vi.fn();
    const useSession = defineSession({
      key,
      maxAge: "1h",
      cookie: { secure: false },
      hooks: {
        async onRead({ session, clear }) {
          if (session.id && session.data.banned) {
            clearSpy();
            await clear();
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

    const meRes = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    jar.update(meRes.headers);

    expect(clearSpy).toHaveBeenCalledTimes(1);

    const clearedRes = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    expect((await clearedRes.json()).id).toBeNull();
  });

  it("forwards onRefresh errors to onError", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const onError = vi.fn();
    const useSession = defineSession({
      key,
      maxAge: "1h",
      refreshAfter: 0.5,
      cookie: { secure: false },
      hooks: {
        onRefresh() {
          throw new Error("db down");
        },
        onError,
      },
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

    vi.setSystemTime(new Date("2026-01-01T00:31:00Z"));

    const meRes = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    const body = await meRes.json();

    expect(onError).toHaveBeenCalledTimes(1);
    expect(onError.mock.calls[0]![0].error).toBeInstanceOf(Error);
    // Session preserved (not cleared on error)
    expect(body.data.userId).toBe("u1");
  });

  it("does not refresh when refreshAfter is false", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const onRefresh = vi.fn();
    const onUpdate = vi.fn();
    const useSession = defineSession({
      key,
      maxAge: "1h",
      refreshAfter: false,
      cookie: { secure: false },
      hooks: { onRefresh, onUpdate },
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

    vi.setSystemTime(new Date("2026-01-01T00:55:00Z"));

    await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    expect(onRefresh).not.toHaveBeenCalled();
    expect(onUpdate).toHaveBeenCalledTimes(1); // only the login
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

    const res = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    expect((await res.json()).id).toBeNull();
  });

  it("calls onRead hook on normal reads (below threshold)", async () => {
    const onRead = vi.fn();
    const useSession = defineSession({
      key,
      maxAge: "1h",
      refreshAfter: 0.5,
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

    await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });

    // onRead called for the GET /me read (below threshold)
    expect(onRead).toHaveBeenCalled();
    expect(onRead.mock.calls[0]![0]).toHaveProperty("clear");
  });

  it("does not call onRead when onRefresh fires", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const onRead = vi.fn();
    const onRefresh = vi.fn();
    const useSession = defineSession({
      key,
      maxAge: "1h",
      refreshAfter: 0.5,
      cookie: { secure: false },
      hooks: { onRead, onRefresh },
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

    // Reset spies after login (which triggers onRead)
    onRead.mockClear();

    vi.setSystemTime(new Date("2026-01-01T00:31:00Z"));

    await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });

    expect(onRefresh).toHaveBeenCalledTimes(1);
    expect(onRead).not.toHaveBeenCalled();
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
      { middleware: [requireSession(useSession)] }
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
      { middleware: [requireSession(useSession, { onAuthenticated })] }
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
      { middleware: [optionalSession(useSession)] }
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
      { middleware: [optionalSession(useSession)] }
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
