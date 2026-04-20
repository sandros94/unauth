import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from "vitest";
import { H3, HTTPError } from "h3";

import {
  type JWK_oct,
  type JWK_Pair,
  generateJWK,
  defineTokenPair,
  requireAuth,
  optionalAuth,
} from "../../src/base/h3/index.ts";

import { cookieJar } from "./_utils.ts";

type AccessData = { sub: string; permissions: string[] };
type RefreshData = { sub: string; family: string };

let atKey: JWK_Pair;
let rtKey: JWK_oct;

beforeAll(async () => {
  atKey = await generateJWK("ES256");
  rtKey = await generateJWK("A256GCMKW");
});

afterEach(() => {
  vi.useRealTimers();
});

function createUseAuth(
  hooks?: Partial<Parameters<typeof defineTokenPair<AccessData, RefreshData>>[0]["hooks"]>,
) {
  return defineTokenPair<AccessData, RefreshData>({
    access: {
      key: atKey,
      maxAge: "15m",
      cookie: { secure: false },
    },
    refresh: {
      key: rtKey,
      maxAge: "30D",
      cookie: { secure: false },
    },
    hooks: {
      async onRefresh({ refresh, issue }) {
        await issue({ accessData: { sub: refresh.data.sub, permissions: ["read"] } });
      },
      ...hooks,
    },
  });
}

describe("defineTokenPair", () => {
  let app: H3;

  beforeEach(() => {
    app = new H3();
  });

  it("throws when access.maxAge is missing", () => {
    expect(() =>
      defineTokenPair<AccessData, RefreshData>({
        access: { key: atKey, maxAge: undefined as any, cookie: { secure: false } },
        refresh: { key: rtKey, maxAge: "30D", cookie: { secure: false } },
        hooks: { onRefresh: vi.fn() },
      }),
    ).toThrow("[unauth] access.maxAge is required");
  });

  it("throws when refresh.maxAge is missing", () => {
    expect(() =>
      defineTokenPair<AccessData, RefreshData>({
        access: { key: atKey, maxAge: "15m", cookie: { secure: false } },
        refresh: { key: rtKey, maxAge: undefined as any, cookie: { secure: false } },
        hooks: { onRefresh: vi.fn() },
      }),
    ).toThrow("[unauth] refresh.maxAge is required");
  });

  it("returns empty sessions initially", async () => {
    const useAuth = createUseAuth();

    app.get("/", async (event) => {
      const { access, refresh } = await useAuth(event);
      return {
        accessId: access.id ?? null,
        refreshId: refresh.id ?? null,
      };
    });

    const res = await app.request("/");
    const body = await res.json();
    expect(body.accessId).toBeNull();
    expect(body.refreshId).toBeNull();
  });

  it("login issues both tokens", async () => {
    const useAuth = createUseAuth();

    app.post("/login", async (event) => {
      const auth = await useAuth(event);
      await auth.issue({
        accessData: { sub: "u1", permissions: ["read", "write"] },
        refreshData: { sub: "u1", family: "fam1" },
      });
      return { ok: true };
    });
    app.get("/me", async (event) => {
      const { access, refresh } = await useAuth(event);
      return {
        accessId: access.id ?? null,
        accessData: access.data,
        refreshId: refresh.id ?? null,
        refreshData: refresh.data,
      };
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    const meRes = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    const body = await meRes.json();

    expect(body.accessId).toBeTypeOf("string");
    expect(body.accessData.sub).toBe("u1");
    expect(body.accessData.permissions).toEqual(["read", "write"]);
    expect(body.refreshId).toBeTypeOf("string");
    expect(body.refreshData.sub).toBe("u1");
    expect(body.refreshData.family).toBe("fam1");
  });

  it("logout clears both tokens and fires onRevoke", async () => {
    const onRevoke = vi.fn();
    const useAuth = createUseAuth({ onRevoke });

    app.post("/login", async (event) => {
      const auth = await useAuth(event);
      await auth.issue({
        accessData: { sub: "u1", permissions: ["read"] },
        refreshData: { sub: "u1", family: "fam1" },
      });
      return { ok: true };
    });
    app.get("/me", async (event) => {
      const { access, refresh } = await useAuth(event);
      return {
        accessId: access.id ?? null,
        refreshId: refresh.id ?? null,
      };
    });
    app.post("/logout", async (event) => {
      const auth = await useAuth(event);
      await auth.revoke();
      return { ok: true };
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    // Verify logged in
    const authedRes = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    const authedBody = await authedRes.json();
    expect(authedBody.accessId).toBeTypeOf("string");
    expect(authedBody.refreshId).toBeTypeOf("string");

    const logoutRes = await app.request("/logout", {
      method: "POST",
      headers: { Cookie: jar.toString() },
    });
    jar.update(logoutRes.headers);

    expect(onRevoke).toHaveBeenCalledTimes(1);

    const meRes = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    const body = await meRes.json();
    expect(body.accessId).toBeNull();
    expect(body.refreshId).toBeNull();
  });

  it("refreshes access token when AT cookie is missing but RT is valid", async () => {
    const useAuth = createUseAuth({
      async onRefresh({ refresh, issue }) {
        await issue({ accessData: { sub: refresh.data.sub, permissions: ["read", "restored"] } });
      },
    });

    app.post("/login", async (event) => {
      const auth = await useAuth(event);
      await auth.issue({
        accessData: { sub: "u1", permissions: ["read"] },
        refreshData: { sub: "u1", family: "fam1" },
      });
      return { ok: true };
    });
    app.get("/me", async (event) => {
      const { access } = await useAuth(event);
      return {
        accessId: access.id ?? null,
        accessData: access.data,
      };
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    // Simulate the browser dropping the AT cookie after Max-Age expires:
    // remove only the AT from the jar, keeping the httpOnly RT intact.
    const rtOnly = cookieJar();
    rtOnly.update(loginRes.headers);
    // Overwrite with a jar that only carries the RT cookie
    const rtOnlyString = rtOnly
      .toString()
      .split("; ")
      .filter((c) => c.startsWith("auth_rt"))
      .join("; ");

    // Request with RT only — AT is missing, should trigger onRefresh
    const refreshRes = await app.request("/me", {
      headers: { Cookie: rtOnlyString },
    });
    jar.update(refreshRes.headers);

    const afterRes = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    const body = await afterRes.json();
    expect(body.accessId).toBeTypeOf("string");
    expect(body.accessData.permissions).toEqual(["read", "restored"]);
  });

  it("refreshes access token when AT is expired via onRefresh + issue()", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const useAuth = createUseAuth({
      async onRefresh({ refresh, issue }) {
        await issue({ accessData: { sub: refresh.data.sub, permissions: ["read", "upgraded"] } });
      },
    });

    app.post("/login", async (event) => {
      const auth = await useAuth(event);
      await auth.issue({
        accessData: { sub: "u1", permissions: ["read"] },
        refreshData: { sub: "u1", family: "fam1" },
      });
      return { ok: true };
    });
    app.get("/me", async (event) => {
      const { access } = await useAuth(event);
      return {
        accessId: access.id ?? null,
        accessData: access.data,
      };
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    // Advance past AT maxAge (15m) but within RT maxAge (30D)
    vi.setSystemTime(new Date("2026-01-01T00:16:00Z"));

    // This triggers onExpire → onRefresh → issue()
    const refreshRes = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    jar.update(refreshRes.headers);

    vi.setSystemTime(new Date("2026-01-01T00:16:01Z"));

    const afterRes = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    const body = await afterRes.json();
    expect(body.accessId).toBeTypeOf("string");
    expect(body.accessData.permissions).toEqual(["read", "upgraded"]);
  });

  it("does not refresh when issue() is not called", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const onRefreshSpy = vi.fn();
    const useAuth = createUseAuth({
      onRefresh: onRefreshSpy,
    });

    app.post("/login", async (event) => {
      const auth = await useAuth(event);
      await auth.issue({
        accessData: { sub: "u1", permissions: ["read"] },
        refreshData: { sub: "u1", family: "fam1" },
      });
      return { ok: true };
    });
    app.get("/me", async (event) => {
      const { access } = await useAuth(event);
      return { accessId: access.id ?? null };
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    vi.setSystemTime(new Date("2026-01-01T00:16:00Z"));

    const meRes = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    jar.update(meRes.headers);

    expect(onRefreshSpy).toHaveBeenCalledTimes(1);

    vi.setSystemTime(new Date("2026-01-01T00:16:01Z"));

    const afterRes = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    expect((await afterRes.json()).accessId).toBeNull();
  });

  it("forwards onRefresh errors to onError without destroying tokens", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const onError = vi.fn();
    const useAuth = createUseAuth({
      onRefresh() {
        throw new Error("db down");
      },
      onError,
    });

    app.post("/login", async (event) => {
      const auth = await useAuth(event);
      await auth.issue({
        accessData: { sub: "u1", permissions: ["read"] },
        refreshData: { sub: "u1", family: "fam1" },
      });
      return { ok: true };
    });
    app.get("/me", async (event) => {
      const { access, refresh } = await useAuth(event);
      return {
        accessId: access.id ?? null,
        refreshId: refresh.id ?? null,
      };
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    vi.setSystemTime(new Date("2026-01-01T00:16:00Z"));

    const meRes = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    jar.update(meRes.headers);
    const body = await meRes.json();

    expect(onError).toHaveBeenCalledTimes(1);
    expect(onError.mock.calls[0]![0].error).toBeInstanceOf(Error);
    expect(onError.mock.calls[0]![0].source).toBe("access");

    // RT preserved on error
    expect(body.refreshId).toBeTypeOf("string");
  });

  it("calls onAfterRefresh with snapshots", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const onAfterRefresh = vi.fn();
    const useAuth = createUseAuth({
      async onRefresh({ refresh, issue }) {
        await issue({ accessData: { sub: refresh.data.sub, permissions: ["refreshed"] } });
      },
      onAfterRefresh,
    });

    app.post("/login", async (event) => {
      const auth = await useAuth(event);
      await auth.issue({
        accessData: { sub: "u1", permissions: ["original"] },
        refreshData: { sub: "u1", family: "fam1" },
      });
      return { ok: true };
    });
    app.get("/me", async (event) => {
      await useAuth(event);
      return { ok: true };
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    vi.setSystemTime(new Date("2026-01-01T00:16:00Z"));

    await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });

    expect(onAfterRefresh).toHaveBeenCalledTimes(1);
    const args = onAfterRefresh.mock.calls[0]![0];

    expect(args.access.data.permissions).toEqual(["refreshed"]);
    expect(args.access.id).toBeTypeOf("string");
    expect(args.previousRefresh.id).toBeTypeOf("string");
    expect(args.refresh.id).toBeTypeOf("string");
  });

  it("rotates refresh token on successful refresh", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const onAfterRefresh = vi.fn();
    const useAuth = createUseAuth({
      async onRefresh({ refresh, issue }) {
        await issue({ accessData: { sub: refresh.data.sub, permissions: ["read"] } });
      },
      onAfterRefresh,
    });

    app.post("/login", async (event) => {
      const auth = await useAuth(event);
      await auth.issue({
        accessData: { sub: "u1", permissions: ["read"] },
        refreshData: { sub: "u1", family: "fam1" },
      });
      return { ok: true };
    });
    app.get("/me", async (event) => {
      await useAuth(event);
      return { ok: true };
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    vi.setSystemTime(new Date("2026-01-01T00:16:00Z"));

    await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });

    expect(onAfterRefresh).toHaveBeenCalledTimes(1);
    const args = onAfterRefresh.mock.calls[0]![0];

    // RT was rotated — new id
    expect(args.previousRefresh.id).not.toBe(args.refresh.id);
  });

  it("does not refresh when RT is missing", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const onRefresh = vi.fn();
    const useAuth = createUseAuth({ onRefresh: onRefresh });

    app.post("/login", async (event) => {
      // Only set AT, no RT
      const { access } = await useAuth(event);
      await access.update({ sub: "u1", permissions: ["read"] });
      return { ok: true };
    });
    app.get("/me", async (event) => {
      const { access } = await useAuth(event);
      return { accessId: access.id ?? null };
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    vi.setSystemTime(new Date("2026-01-01T00:16:00Z"));

    await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });

    // onRefresh should not be called — no RT
    expect(onRefresh).not.toHaveBeenCalled();
  });

  it("calls onReadAccess when access token is read", async () => {
    const onReadAccess = vi.fn();
    const useAuth = createUseAuth({ onReadAccess });

    app.post("/login", async (event) => {
      const auth = await useAuth(event);
      await auth.issue({
        accessData: { sub: "u1", permissions: ["read"] },
        refreshData: { sub: "u1", family: "fam1" },
      });
      return { ok: true };
    });
    app.get("/me", async (event) => {
      await useAuth(event);
      return { ok: true };
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });

    expect(onReadAccess).toHaveBeenCalledTimes(1);
    expect(onReadAccess.mock.calls[0]![0].access.data.sub).toBe("u1");
  });

  it("calls onReadRefresh when refresh token is read", async () => {
    const onReadRefresh = vi.fn();
    const useAuth = createUseAuth({ onReadRefresh });

    app.post("/login", async (event) => {
      const auth = await useAuth(event);
      await auth.issue({
        accessData: { sub: "u1", permissions: ["read"] },
        refreshData: { sub: "u1", family: "fam1" },
      });
      return { ok: true };
    });
    app.get("/me", async (event) => {
      await useAuth(event);
      return { ok: true };
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });

    expect(onReadRefresh).toHaveBeenCalledTimes(1);
    expect(onReadRefresh.mock.calls[0]![0].refresh.data.family).toBe("fam1");
  });

  it("does not call onReadAccess when no access token exists", async () => {
    const onReadAccess = vi.fn();
    const useAuth = createUseAuth({ onReadAccess });

    app.get("/", async (event) => {
      await useAuth(event);
      return { ok: true };
    });

    await app.request("/");
    expect(onReadAccess).not.toHaveBeenCalled();
  });

  it("revokes both tokens from onRefresh via revoke()", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const useAuth = createUseAuth({
      async onRefresh({ revoke }) {
        await revoke();
      },
    });

    app.post("/login", async (event) => {
      const auth = await useAuth(event);
      await auth.issue({
        accessData: { sub: "u1", permissions: ["read"] },
        refreshData: { sub: "u1", family: "fam1" },
      });
      return { ok: true };
    });
    app.get("/me", async (event) => {
      const { access, refresh } = await useAuth(event);
      return {
        accessId: access.id ?? null,
        refreshId: refresh.id ?? null,
      };
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    vi.setSystemTime(new Date("2026-01-01T00:16:00Z"));

    const refreshRes = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    jar.update(refreshRes.headers);

    vi.setSystemTime(new Date("2026-01-01T00:16:01Z"));

    const afterRes = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    const body = await afterRes.json();
    // Both tokens should be gone — revoke() cleared the RT,
    // and the AT was already expired
    expect(body.accessId).toBeNull();
    expect(body.refreshId).toBeNull();
  });

  it("exposes underlying session managers for escape-hatch", async () => {
    const useAuth = createUseAuth();

    app.post("/login", async (event) => {
      const auth = await useAuth(event);
      await auth.issue({
        accessData: { sub: "u1", permissions: ["read"] },
        refreshData: { sub: "u1", family: "fam1" },
      });
      return { ok: true };
    });
    app.post("/force-update", async (event) => {
      const { access } = await useAuth(event);
      await access.update({ sub: "u1", permissions: ["admin"] });
      return { ok: true };
    });
    app.get("/me", async (event) => {
      const { access } = await useAuth(event);
      return { permissions: access.data.permissions };
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    const updateRes = await app.request("/force-update", {
      method: "POST",
      headers: { Cookie: jar.toString() },
    });
    jar.update(updateRes.headers);

    const meRes = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    const body = await meRes.json();
    expect(body.permissions).toEqual(["admin"]);
  });
});

describe("requireAuth", () => {
  let app: H3;

  beforeEach(() => {
    app = new H3();
  });

  it("passes when access token is present", async () => {
    const useAuth = createUseAuth();

    app.post("/login", async (event) => {
      const auth = await useAuth(event);
      await auth.issue({
        accessData: { sub: "u1", permissions: ["read"] },
        refreshData: { sub: "u1", family: "fam1" },
      });
      return { ok: true };
    });
    app.get(
      "/me",
      async (event) => {
        const { access } = await useAuth(event);
        return { sub: access.data.sub };
      },
      { middleware: [requireAuth(useAuth)] },
    );

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    const meRes = await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });
    expect(meRes.status).toBe(200);
    expect((await meRes.json()).sub).toBe("u1");
  });

  it("throws 401 when no access token", async () => {
    const useAuth = createUseAuth();

    app.get("/me", () => ({ ok: true }), { middleware: [requireAuth(useAuth)] });

    const res = await app.request("/me");
    expect(res.status).toBe(401);
  });

  it("calls onAuthenticated hook", async () => {
    const onAuthenticated = vi.fn();
    const useAuth = createUseAuth();

    app.post("/login", async (event) => {
      const auth = await useAuth(event);
      await auth.issue({
        accessData: { sub: "u1", permissions: ["read"] },
        refreshData: { sub: "u1", family: "fam1" },
      });
      return { ok: true };
    });
    app.get("/me", () => ({ ok: true }), {
      middleware: [requireAuth(useAuth, { onAuthenticated })],
    });

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    await app.request("/me", {
      headers: { Cookie: jar.toString() },
    });

    expect(onAuthenticated).toHaveBeenCalledTimes(1);
    expect(onAuthenticated.mock.calls[0]![0].session.data.sub).toBe("u1");
  });

  it("propagates onAuthenticated errors", async () => {
    const useAuth = createUseAuth();

    app.post("/login", async (event) => {
      const auth = await useAuth(event);
      await auth.issue({
        accessData: { sub: "u1", permissions: ["read"] },
        refreshData: { sub: "u1", family: "fam1" },
      });
      return { ok: true };
    });
    app.get("/admin", () => ({ ok: true }), {
      middleware: [
        requireAuth(useAuth, {
          onAuthenticated({ session }) {
            if (!session.data.permissions.includes("admin")) {
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

describe("optionalAuth", () => {
  let app: H3;

  beforeEach(() => {
    app = new H3();
  });

  it("passes when authenticated", async () => {
    const useAuth = createUseAuth();

    app.post("/login", async (event) => {
      const auth = await useAuth(event);
      await auth.issue({
        accessData: { sub: "u1", permissions: ["read"] },
        refreshData: { sub: "u1", family: "fam1" },
      });
      return { ok: true };
    });
    app.get(
      "/feed",
      async (event) => {
        const { access } = await useAuth(event);
        return { authenticated: !!access.id, sub: access.data.sub ?? null };
      },
      { middleware: [optionalAuth(useAuth)] },
    );

    const jar = cookieJar();

    const loginRes = await app.request("/login", { method: "POST" });
    jar.update(loginRes.headers);

    const feedRes = await app.request("/feed", {
      headers: { Cookie: jar.toString() },
    });
    const body = await feedRes.json();
    expect(body.authenticated).toBe(true);
    expect(body.sub).toBe("u1");
  });

  it("passes when unauthenticated", async () => {
    const useAuth = createUseAuth();

    app.get(
      "/feed",
      async (event) => {
        const { access } = await useAuth(event);
        return { authenticated: !!access.id };
      },
      { middleware: [optionalAuth(useAuth)] },
    );

    const res = await app.request("/feed");
    const body = await res.json();
    expect(body.authenticated).toBe(false);
  });

  it("calls onAuthenticated only when authenticated", async () => {
    const onAuthenticated = vi.fn();
    const useAuth = createUseAuth();

    app.get("/feed", () => ({ ok: true }), {
      middleware: [optionalAuth(useAuth, { onAuthenticated })],
    });

    await app.request("/feed");
    expect(onAuthenticated).not.toHaveBeenCalled();
  });
});
