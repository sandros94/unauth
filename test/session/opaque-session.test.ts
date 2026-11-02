import { afterEach, beforeEach, describe, expect, expectTypeOf, it, vi } from "vitest";
import {
  type JWK_oct,
  type WebSessionEvent,
  defineJWSSession,
  defineSessionDriver,
  generateJWK,
} from "unjwt/session";
import type { CacheDriver } from "../../src/_internal/cache-driver.ts";
import { isUnauthError } from "../../src/error.ts";
import { hashOpaqueToken } from "../../src/token/opaque-token.ts";
import {
  type OpaqueSessionManager,
  type OpaqueSessionUpdate,
  defineOpaqueSession,
} from "../../src/session/index.ts";

interface Data {
  userId: string;
  name?: string;
}

const NOW = Date.UTC(2026, 0, 1, 12);
const HOUR = 60 * 60_000;

beforeEach(() => {
  vi.useFakeTimers({ now: NOW });
});
afterEach(() => {
  vi.useRealTimers();
});

describe("defineOpaqueSession", () => {
  it("creates a session on update: a cookie with the token, a record under its hash with a ttl", async () => {
    const { store, entries } = memory();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h" });
    const event = request();
    const session = await sessions.use(event);
    expect(session.id).toBeUndefined();
    expect(session.token).toBeUndefined();
    expect(session.data).toEqual({});
    expect(session.createdAt).toBe(NOW);
    expect(session.updatedAt).toBe(NOW);
    expect(session.expiresAt).toBe(NOW + HOUR);
    expect(session.error).toBeUndefined();
    expect(session.source).toBe("cookie");

    vi.setSystemTime(NOW + 1000);
    expect(await session.update({ userId: "u1" })).toBe(session);
    const line = cookieLine(event);
    const token = cookieValue(line);
    expect(token).toMatch(/^[\w-]{43}$/);
    expect(line).toContain(`Expires=${new Date(NOW + 1000 + HOUR).toUTCString()}`);
    expect(line).toContain("HttpOnly");
    expect(line).toContain("Secure");
    expect(line).toContain("SameSite=Lax");
    expect(event.res.errHeaders.getSetCookie()).toEqual([line]);
    expect(event.res.headers.getSetCookie()).toHaveLength(1);

    const hash = await hashOpaqueToken(token);
    expect(session.id).toBe(hash);
    expect(session.token).toBe(token);
    expect(session.createdAt).toBe(NOW + 1000);
    expect(session.updatedAt).toBe(NOW + 1000);
    expect(session.expiresAt).toBe(NOW + 1000 + HOUR);
    expect(session.data).toEqual({ userId: "u1" });
    expect(entries.get(hash)).toEqual({
      value: {
        createdAt: NOW + 1000,
        updatedAt: NOW + 1000,
        expiresAt: NOW + 1000 + HOUR,
        data: { userId: "u1" },
      },
      ttl: 3600,
    });
    expect(sessions.token(event)).toBe(token);
    expect(await sessions.use(event)).toBe(session);
  });

  it("reads the session back; update merges the data, moves updatedAt, keeps the token and the expiry", async () => {
    const { store, entries } = memory();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h" });
    const token = await signIn(sessions, { userId: "u1" });

    vi.setSystemTime(NOW + 5000);
    const event = request({ cookie: `__Host-unauth=${token}` });
    const session = await sessions.use(event);
    expect(session.id).toBe(await hashOpaqueToken(token));
    expect(session.token).toBe(token);
    expect(session.data).toEqual({ userId: "u1" });
    expect(event.res.headers.getSetCookie()).toEqual([]);

    await session.update((data) => ({ name: `${data.userId}!` }));
    expect(session.data).toEqual({ userId: "u1", name: "u1!" });
    expect(session.token).toBe(token);
    expect(session.updatedAt).toBe(NOW + 5000);
    expect(session.expiresAt).toBe(NOW + HOUR);
    expect(cookieValue(cookieLine(event))).toBe(token);
    expect(cookieLine(event)).toContain(new Date(NOW + HOUR).toUTCString());
    expect(entries.size).toBe(1);
    expect(entries.get(session.id!)?.value).toMatchObject({
      updatedAt: NOW + 5000,
      data: { userId: "u1", name: "u1!" },
    });

    await session.update(() => undefined);
    expect(session.data).toEqual({ userId: "u1", name: "u1!" });
  });

  it("refuses an update that is not a plain object", async () => {
    const { store, entries } = memory();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h" });
    const event = request();
    const session = await sessions.use(event);
    for (const junk of [null, [], "x", () => "x"]) {
      await expect(
        // @ts-expect-error -- not an update
        session.update(junk),
      ).rejects.toThrow(TypeError);
    }
    expect(entries.size).toBe(0);
    expect(event.res.headers.getSetCookie()).toEqual([]);
    await expect(session.rotate()).rejects.toThrow(TypeError);

    await session.update();
    expect(session.id).toBeDefined();
    expect(session.data).toEqual({});
  });

  it("rolling extends a cookie session once past its point, measured from the last extension", async () => {
    const { store, entries } = memory();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h", rolling: "15m" });
    const token = await signIn(sessions, { userId: "u1" });

    vi.setSystemTime(NOW + 10 * 60_000);
    const early = request({ cookie: `__Host-unauth=${token}` });
    const first = await sessions.use(early);
    expect(first.expiresAt).toBe(NOW + HOUR);
    expect(early.res.headers.getSetCookie()).toEqual([]);
    await first.update({ name: "busy" });
    expect(first.expiresAt).toBe(NOW + HOUR);

    vi.setSystemTime(NOW + 20 * 60_000);
    const late = request({ cookie: `__Host-unauth=${token}` });
    const second = await sessions.use(late);
    expect(second.expiresAt).toBe(NOW + 20 * 60_000 + HOUR);
    expect(second.updatedAt).toBe(NOW + 20 * 60_000);
    expect(second.createdAt).toBe(NOW);
    expect(cookieValue(cookieLine(late))).toBe(token);
    expect(cookieLine(late)).toContain(new Date(NOW + 20 * 60_000 + HOUR).toUTCString());
    expect(entries.get(second.id!)?.ttl).toBe(3600);

    vi.setSystemTime(NOW + 30 * 60_000);
    const soon = request({ cookie: `__Host-unauth=${token}` });
    expect((await sessions.use(soon)).expiresAt).toBe(NOW + 20 * 60_000 + HOUR);
    expect(soon.res.headers.getSetCookie()).toEqual([]);

    const readonly = { req: request({ cookie: `__Host-unauth=${token}` }).req };
    vi.setSystemTime(NOW + 50 * 60_000);
    expect((await sessions.use(readonly)).expiresAt).toBe(NOW + 20 * 60_000 + HOUR);
  });

  it("rolling: true extends on every read", async () => {
    const { store } = memory();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h", rolling: true });
    const token = await signIn(sessions, { userId: "u1" });
    vi.setSystemTime(NOW + 1000);
    const event = request({ cookie: `__Host-unauth=${token}` });
    expect((await sessions.use(event)).expiresAt).toBe(NOW + 1000 + HOUR);
    expect(cookieLine(event)).toContain(new Date(NOW + 1000 + HOUR).toUTCString());
  });

  it("drops an expired session: error, cookie expired, record removed", async () => {
    const { store, entries } = memory();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h", prefix: "s:" });
    const token = await signIn(sessions, { userId: "u1" });
    expect([...entries.keys()][0]).toMatch(/^s:/);
    vi.setSystemTime(NOW + HOUR);
    const event = request({ cookie: `__Host-unauth=${token}` });
    const session = await sessions.use(event);
    expect(session.id).toBeUndefined();
    expect(session.data).toEqual({});
    expect(isUnauthError(session.error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
    expect(session.error?.cause).toEqual({ reason: "expired" });
    expect(session.error?.status).toBe(401);
    expect(session.error?.message).toBe("[unauth/session] The session token is not valid.");
    expect(cookieLine(event)).toContain("Max-Age=0");
    expect(entries.size).toBe(0);
    expect(sessions.token(event)).toBe(token);
  });

  it("refuses a token that names no record, shaped or not, and a corrupted record", async () => {
    const { store, entries } = memory();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h" });
    for (const value of ["abc", "A".repeat(43), "bad value!", "A".repeat(513)]) {
      const event = request({ cookie: `__Host-unauth=${value}` });
      const session = await sessions.use(event);
      expect(session.error?.cause).toEqual({ reason: "unknown" });
      expect(cookieLine(event)).toContain("Max-Age=0");
    }
    const token = await signIn(sessions, { userId: "u1" });
    const key = await hashOpaqueToken(token);
    entries.set(key, {
      value: { createdAt: "x", updatedAt: NOW, expiresAt: NOW + HOUR, data: {} },
    });
    const session = await sessions.use(request({ cookie: `__Host-unauth=${token}` }));
    expect(session.error?.cause).toEqual({ reason: "unknown" });
    expect(entries.has(key)).toBe(false);
  });

  it("is read-only without a response", async () => {
    const { store } = memory();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h" });
    const token = await signIn(sessions, { userId: "u1" });
    const session = await sessions.use({ req: request({ cookie: `__Host-unauth=${token}` }).req });
    expect(session.data).toEqual({ userId: "u1" });
    const thrown = await session.update({ name: "x" }).catch((error: unknown) => error);
    expect(isUnauthError(thrown, "ERR_SESSION_READONLY_EVENT")).toBe(true);
    expect(isUnauthError(thrown) && thrown.status).toBe(500);
  });

  it("clear removes the record and expires the cookie; the token names nothing after", async () => {
    const { store, entries } = memory();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h", prefix: "s:" });
    const token = await signIn(sessions, { userId: "u1" });
    const event = request({ cookie: `__Host-unauth=${token}` });
    const session = await sessions.use(event);
    expect(await session.clear()).toBe(session);
    expect(session.id).toBeUndefined();
    expect(session.token).toBeUndefined();
    expect(session.data).toEqual({});
    expect(session.error).toBeUndefined();
    expect(entries.size).toBe(0);
    expect(cookieLine(event)).toContain("Max-Age=0");
    expect(sessions.token(event)).toBeUndefined();
    const again = await sessions.use(request({ cookie: `__Host-unauth=${token}` }));
    expect(again.error?.cause).toEqual({ reason: "unknown" });

    await session.update({ userId: "u2" });
    expect(session.token).not.toBe(token);
    expect(cookieValue(cookieLine(event))).toBe(session.token);
    expect(event.res.headers.getSetCookie()).toHaveLength(1);
  });

  it("rotate moves the session under a new token; createdAt and updatedAt move, data and expiry stay", async () => {
    const { store, entries } = memory();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h" });
    const token = await signIn(sessions, { userId: "u1" });
    vi.setSystemTime(NOW + 1000);
    const event = request({ cookie: `__Host-unauth=${token}` });
    const session = await sessions.use(event);
    expect(await session.rotate()).toBe(session);
    expect(session.token).not.toBe(token);
    expect(session.id).toBe(await hashOpaqueToken(session.token!));
    expect(session.createdAt).toBe(NOW + 1000);
    expect(session.updatedAt).toBe(NOW + 1000);
    expect(session.expiresAt).toBe(NOW + HOUR);
    expect(session.data).toEqual({ userId: "u1" });
    expect(cookieValue(cookieLine(event))).toBe(session.token);
    expect([...entries.keys()]).toEqual([session.id]);
    expect(sessions.token(event)).toBe(session.token);
    const old = await sessions.use(request({ cookie: `__Host-unauth=${token}` }));
    expect(old.error?.cause).toEqual({ reason: "unknown" });
  });

  it("rotate fails closed: a store that cannot write the new record leaves no session", async () => {
    const { store, entries } = memory();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h" });
    const token = await signIn(sessions, { userId: "u1" });
    const event = request({ cookie: `__Host-unauth=${token}` });
    const session = await sessions.use(event);
    store.set = (key, value) => {
      if (value !== null) throw new Error("store down");
      entries.delete(key);
    };
    await expect(session.rotate()).rejects.toThrow("store down");
    expect(session.id).toBeUndefined();
    expect(session.token).toBeUndefined();
    expect(entries.size).toBe(0);
    expect(event.res.headers.getSetCookie()).toEqual([]);
  });

  it("a store that throws fails the read, and every later use of the request", async () => {
    const { store } = memory();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h" });
    const token = await signIn(sessions, { userId: "u1" });
    store.get = () => {
      throw new Error("store down");
    };
    const event = request({ cookie: `__Host-unauth=${token}` });
    await expect(sessions.use(event)).rejects.toThrow("store down");
    await expect(sessions.use(event)).rejects.toThrow("store down");
    expect(await (await sessions.use(request())).update({ userId: "u2" })).toBeDefined();
  });

  it("concurrent use() calls share one read and one manager", async () => {
    const { store } = memory();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h" });
    const token = await signIn(sessions, { userId: "u1" });
    const get = vi.spyOn(store, "get");
    const event = request({ cookie: `__Host-unauth=${token}` });
    const [a, b] = await Promise.all([sessions.use(event), sessions.use(event)]);
    expect(a).toBe(b);
    expect(get).toHaveBeenCalledTimes(1);
  });

  it("session header: a bearer is read, changes reach the store alone, clear revokes it", async () => {
    const { store, entries } = memory();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h", sessionHeader: true });
    const start = request();
    const created = await sessions.use(start);
    await created.update({ userId: "u1" });
    expect(cookieValue(cookieLine(start))).toBe(created.token);

    const api = request({ headers: { "x-unauth-session": `Bearer ${created.token}` } });
    const session = await sessions.use(api);
    expect(session.source).toBe("header");
    expect(session.data).toEqual({ userId: "u1" });
    await session.update({ name: "n" });
    expect(api.res.headers.getSetCookie()).toEqual([]);
    expect(entries.get(session.id!)?.value).toMatchObject({ data: { userId: "u1", name: "n" } });

    const before = session.token;
    await session.rotate();
    expect(api.res.headers.getSetCookie()).toEqual([]);
    expect(session.token).not.toBe(before);
    expect(sessions.token(api)).toBe(session.token);

    await session.clear();
    expect(entries.size).toBe(0);
    expect(api.res.headers.getSetCookie()).toEqual([]);
  });

  it("no cookie: a session lives in the header alone, and a new one on token", async () => {
    const { store } = memory();
    const sessions = defineOpaqueSession<Data>({
      store,
      maxAge: "1h",
      cookie: false,
      sessionHeader: "authorization",
    });
    const event = request();
    const session = await sessions.use(event);
    expect(session.source).toBe("header");
    await session.update({ userId: "u1" });
    expect(event.res.headers.getSetCookie()).toEqual([]);
    expect(session.token).toBeDefined();
    expect(sessions.token(event)).toBe(session.token);
    const next = request({ headers: { authorization: `Bearer ${session.token}` } });
    expect((await sessions.use(next)).data).toEqual({ userId: "u1" });
  });

  it("no cookie, no header: tokens in hand alone; a request has nothing to read", async () => {
    const { store } = memory();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h", cookie: false });
    const token = await sessions.issue({ userId: "u1" });
    expect((await sessions.open(token)).data).toEqual({ userId: "u1" });
    const session = await sessions.use({ token });
    expect(session.source).toBe("token");
    await session.clear();
    expect((await sessions.use({ token })).error?.cause).toEqual({ reason: "unknown" });
    const thrown = await sessions.use(request()).catch((error: unknown) => error);
    expect(isUnauthError(thrown, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    expect(isUnauthError(thrown) && thrown.message).toMatch(/token source/);
  });

  it("session header: a bearer holding the cookie's token is the cookie session", async () => {
    const { store } = memory();
    const sessions = defineOpaqueSession<Data>({
      store,
      maxAge: "1h",
      sessionHeader: "authorization",
    });
    const token = await signIn(sessions, { userId: "u1" });
    const event = request({
      cookie: `__Host-unauth=${token}`,
      headers: { authorization: `Bearer ${token}` },
    });
    expect((await sessions.use(event)).source).toBe("cookie");
  });

  it("session header without a token: error header, the cookie untouched", async () => {
    const { store } = memory();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h", sessionHeader: true });
    const event = request({ headers: { "x-unauth-session": "not a token" } });
    const session = await sessions.use(event);
    expect(session.id).toBeUndefined();
    expect(session.error?.cause).toEqual({ reason: "header", header: "x-unauth-session" });
    expect(event.res.headers.getSetCookie()).toEqual([]);
  });

  it("a token in hand is a token session: a store write, no cookie", async () => {
    const { store } = memory();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h" });
    const token = await sessions.issue({ userId: "u1" });
    const handed = { token };
    const session = await sessions.use(handed);
    expect(session.source).toBe("token");
    expect(session.data).toEqual({ userId: "u1" });
    await session.rotate();
    expect(sessions.token(handed)).toBe(session.token);
    expect((await sessions.use({ token: session.token })).data).toEqual({ userId: "u1" });
    expect((await sessions.use({ token })).error?.cause).toEqual({ reason: "unknown" });
  });

  it("issue and open: a record without a request, a token's session from the store", async () => {
    const { store, entries } = memory();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "2h", prefix: "s:" });
    const token = await sessions.issue({ userId: "u1" });
    const hash = await hashOpaqueToken(token);
    expect([...entries.keys()]).toEqual([`s:${hash}`]);
    expect(entries.get(`s:${hash}`)?.ttl).toBe(7200);
    expect(await sessions.open(token)).toEqual({
      id: hash,
      token,
      source: "token",
      createdAt: NOW,
      updatedAt: NOW,
      expiresAt: NOW + 2 * HOUR,
      data: { userId: "u1" },
    });
    const thrown = await sessions.open("nope").catch((error: unknown) => error);
    expect(isUnauthError(thrown, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
    vi.setSystemTime(NOW + 2 * HOUR);
    const expired = await sessions.open(token).catch((error: unknown) => error);
    expect(isUnauthError(expired, "ERR_SESSION_TOKEN_INVALID") && expired.cause).toEqual({
      reason: "expired",
    });
    expect(entries.size).toBe(0);
  });

  it("runs over a framework driver of its own", async () => {
    const { store } = memory();
    interface AppEvent {
      cookies: Record<string, string>;
      written: Record<string, string>;
      bag: Record<string, unknown>;
    }
    const driver = defineSessionDriver<AppEvent>({
      prefix: "[app]",
      state: (event) => event.bag,
      header: () => undefined,
      cookies: (event) => ({
        read: (name) => event.cookies[name],
        write: (name, value) => {
          event.written[name] = value;
        },
      }),
    });
    const sessions = defineOpaqueSession<Data, AppEvent>({ store, maxAge: "1h" }, { driver });
    const first: AppEvent = { cookies: {}, written: {}, bag: {} };
    const session = await sessions.use(first);
    await session.update({ userId: "u1" });
    expect(first.written["__Host-unauth"]).toBe(session.token);
    const second: AppEvent = { cookies: { "__Host-unauth": session.token! }, written: {}, bag: {} };
    expect((await sessions.use(second)).data).toEqual({ userId: "u1" });
    const bad = await sessions.use(first).catch((error: unknown) => error);
    expect(bad).toBe(session);
  });

  it("refuses an event the driver does not take as a config error", async () => {
    const { store } = memory();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h" });
    // @ts-expect-error -- neither a request event nor a token
    const thrown = await sessions.use({}).catch((error: unknown) => error);
    expect(isUnauthError(thrown, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    expect(isUnauthError(thrown) && thrown.message).toMatch(/^\[unauth\/session\]/);
  });

  it("refuses a name another kind of session bound on the request", async () => {
    const { store } = memory();
    const key: JWK_oct<"HS256"> = await generateJWK("HS256");
    const jws = defineJWSSession({ key, name: "__Host-unauth" });
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h" });
    const event = request();
    await jws.use(event);
    const thrown = await sessions.use(event).catch((error: unknown) => error);
    expect(isUnauthError(thrown, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    expect(isUnauthError(thrown) && thrown.message).toMatch(/^\[unauth\/session\] .*JWS/);
  });

  it("takes up to 384 random bytes per token, and reads such a token back", async () => {
    const { store } = memory();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h", bytes: 384 });
    const event = request();
    const session = await sessions.use(event);
    await session.update({ userId: "u1" });
    expect(session.token).toHaveLength(512);
    const next = request({ cookie: `__Host-unauth=${session.token}` });
    expect((await sessions.use(next)).data).toEqual({ userId: "u1" });
  });

  it("refuses a config that cannot work", () => {
    const { store } = memory();
    const refused = (config: Parameters<typeof defineOpaqueSession>[0]) => {
      try {
        defineOpaqueSession(config);
      } catch (error) {
        return isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID") ? error.message : error;
      }
      return undefined;
    };
    expect(refused({ store, maxAge: "0s" })).toMatch(/^\[unauth\/session\] A session needs/);
    expect(refused({ store, maxAge: "1h", rolling: "2h" })).toMatch(/"rolling" must be shorter/);
    expect(refused({ store, maxAge: "1h", bytes: 8 })).toMatch(/16 to 384/);
    expect(refused({ store, maxAge: "1h", bytes: 385 })).toMatch(/16 to 384/);
    expect(refused({ store, maxAge: "1h", cookie: { secure: false } })).toMatch(/__Host-/);
    expect(refused({ store, maxAge: "1h", sessionHeader: "bad header" })).toMatch(/sessionHeader/);
    expect(refused({ store, maxAge: "1h", name: "session", cookie: { secure: false } })).toBe(
      undefined,
    );
  });

  it("types the manager as one object for the request", async () => {
    const { store } = memory();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h" });
    const session = await sessions.use(request());
    expectTypeOf(session).toEqualTypeOf<OpaqueSessionManager<Data>>();
    expectTypeOf(session.id).toEqualTypeOf<string | undefined>();
    expectTypeOf(session.data).toEqualTypeOf<Data>();
    expectTypeOf(session.createdAt).toEqualTypeOf<number>();
    expectTypeOf<Parameters<OpaqueSessionManager<Data>["update"]>[0]>().toEqualTypeOf<
      OpaqueSessionUpdate<Data> | undefined
    >();
    expectTypeOf<Awaited<ReturnType<OpaqueSessionManager<Data>["clear"]>>>().toEqualTypeOf<
      OpaqueSessionManager<Data>
    >();
    expectTypeOf<Parameters<typeof sessions.use>[0]>().toEqualTypeOf<WebSessionEvent>();
  });
});

function memory() {
  const entries = new Map<string, { value: unknown; ttl?: number }>();
  const store: CacheDriver = {
    // oxlint-disable-next-line typescript/no-unnecessary-type-parameters -- `CacheDriver.get` types the value at its call site
    get: <T>(key: string) => {
      const entry = entries.get(key);
      return entry ? (structuredClone(entry.value) as T) : null;
    },
    set: (key, value, options) => {
      if (value === null) entries.delete(key);
      else entries.set(key, { value: structuredClone(value), ttl: options?.ttl });
    },
  };
  return { store, entries };
}

function request(options?: { cookie?: string; headers?: Record<string, string> }) {
  const headers = new Headers(options?.headers);
  if (options?.cookie) headers.set("cookie", options.cookie);
  return {
    req: new Request("https://app.test/", { headers }),
    res: { headers: new Headers(), errHeaders: new Headers() },
  };
}

async function signIn(
  sessions: ReturnType<typeof defineOpaqueSession<Data>>,
  data: Data,
): Promise<string> {
  const event = request();
  await (await sessions.use(event)).update(data);
  return cookieValue(cookieLine(event));
}

function cookieLine(event: ReturnType<typeof request>): string {
  const line = event.res.headers.getSetCookie().find((set) => set.startsWith("__Host-unauth="));
  if (!line) throw new Error("no session cookie");
  return line;
}

function cookieValue(line: string): string {
  return line.slice(line.indexOf("=") + 1, line.indexOf(";"));
}
