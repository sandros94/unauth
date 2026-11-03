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
import {
  type OpaqueSession,
  type OpaqueSessionConfig,
  type OpaqueSessionNone,
  type OpaqueSessionRecord,
  type OpaqueSessionStore,
  defineOpaqueSession,
  kvSessionStore,
} from "../../src/session/index.ts";

interface Data {
  userId: string;
  name?: string;
}

const NOW = Date.UTC(2026, 0, 1, 12);
const HOUR = 60 * 60_000;
const DAY = 24 * HOUR;

beforeEach(() => {
  vi.useFakeTimers({ now: NOW });
});
afterEach(() => {
  vi.useRealTimers();
});

describe("defineOpaqueSession", () => {
  it("use() touches no store; data is the one read, shared by the request", async () => {
    const { store, calls } = counted();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "30D" });
    const token = await sessions.issue({ userId: "u1" });
    expect(calls()).toEqual({ save: 1 });

    const event = request({ cookie: `__Host-unauth=${token}` });
    const session = sessions.use(event);
    expect(sessions.use(event)).toBe(session);
    expect(session.token).toBe(token);
    expect(session.source).toBe("cookie");
    expect(session.error).toBeUndefined();
    expect(calls()).toEqual({ save: 1 });

    const [a, b] = await Promise.all([session.record, sessions.use(event).record]);
    expect(a.data).toEqual({ userId: "u1" });
    expect(b).toBe(a);
    expect(await session.record).toBe(a);
    expect(calls()).toEqual({ save: 1, find: 1 });
    expect(event.res.headers.getSetCookie()).toEqual([]);
  });

  it("creates a session on the first update with data: a cookie whose Expires is the absolute end", async () => {
    const { store, rows } = counted();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "30D", idle: "7D" });
    const event = request();
    const session = sessions.use(event);
    expect(session.token).toBeUndefined();
    expect((await session.record).data).toBeUndefined();
    expect(await session.record).toEqual({
      id: undefined,
      createdAt: undefined,
      updatedAt: undefined,
      expiresAt: undefined,
      data: undefined,
    });

    expect(await session.update({})).toBeUndefined();
    expect(await session.update(() => undefined)).toBeUndefined();
    expect(rows.size).toBe(0);
    expect(event.res.headers.getSetCookie()).toEqual([]);

    const created = await session.update({ userId: "u1" });
    expect(created?.data).toEqual({ userId: "u1" });
    const line = cookieLine(event);
    const token = cookieValue(line);
    expect(token).toMatch(/^[\w-]{43}$/);
    expect(session.token).toBe(token);
    expect(line).toContain(`Expires=${new Date(NOW + 30 * DAY).toUTCString()}`);
    expect(line).toContain("HttpOnly");
    expect(event.res.errHeaders.getSetCookie()).toEqual([line]);
    const record = rows.get(token);
    expect(record).toEqual({
      id: expect.stringMatching(/^[0-9a-f-]{36}$/),
      createdAt: NOW,
      updatedAt: NOW,
      expiresAt: NOW + 7 * DAY,
      data: { userId: "u1" },
    });
    expect(created).toEqual(record);
    expect(await session.record).toEqual(record);
    expect((await session.record).data).toEqual({ userId: "u1" });
    expect(session.error).toBeUndefined();
  });

  it("a session without maxAge gets a browser-session cookie and an idle end", async () => {
    const { store, rows } = counted();
    const sessions = defineOpaqueSession<Data>({ store, idle: "14D" });
    const event = request();
    await sessions.use(event).update({ userId: "u1" });
    const line = cookieLine(event);
    expect(line).not.toContain("Expires=");
    expect(line).not.toContain("Max-Age=");
    expect(rows.get(cookieValue(line))?.expiresAt).toBe(NOW + 14 * DAY);

    const forever = defineOpaqueSession<Data>({ store });
    const other = request();
    await forever.use(other).update({ userId: "u2" });
    expect(rows.get(cookieValue(cookieLine(other)))?.expiresAt).toBeUndefined();
  });

  it("update on a live session rewrites the record alone: token and cookie untouched, idle clock restarted", async () => {
    const { store, rows, calls } = counted();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "30D", idle: "7D" });
    const token = await sessions.issue({ userId: "u1" });
    vi.setSystemTime(NOW + HOUR);
    const event = request({ cookie: `__Host-unauth=${token}` });
    const session = sessions.use(event);
    expect((await session.update((data) => ({ name: `${data?.userId}!` })))?.data).toEqual({
      userId: "u1",
      name: "u1!",
    });
    expect(await session.record).toMatchObject({
      updatedAt: NOW + HOUR,
      expiresAt: NOW + HOUR + 7 * DAY,
    });
    expect(session.token).toBe(token);
    expect(event.res.headers.getSetCookie()).toEqual([]);
    expect(rows.get(token)).toMatchObject({
      createdAt: NOW,
      updatedAt: NOW + HOUR,
      expiresAt: NOW + HOUR + 7 * DAY,
      data: { userId: "u1", name: "u1!" },
    });
    expect(calls()).toEqual({ save: 2, find: 1 });
    expect((await session.record).data).toEqual({ userId: "u1", name: "u1!" });
    for (const junk of [null, [], "x", () => "x"]) {
      // @ts-expect-error -- not an update
      await expect(session.update(junk)).rejects.toThrow(TypeError);
    }
  });

  it("a read extends an idle session once half the idle time passed, through touch alone", async () => {
    const { store, rows, calls } = counted();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "30D", idle: "8h" });
    const token = await sessions.issue({ userId: "u1" });

    vi.setSystemTime(NOW + 3 * HOUR);
    const early = request({ cookie: `__Host-unauth=${token}` });
    expect((await sessions.use(early).record).data).toEqual({ userId: "u1" });
    expect(calls()).toEqual({ save: 1, find: 1 });
    expect(rows.get(token)?.expiresAt).toBe(NOW + 8 * HOUR);

    vi.setSystemTime(NOW + 4 * HOUR);
    const due = request({ cookie: `__Host-unauth=${token}` });
    expect((await sessions.use(due).record).data).toEqual({ userId: "u1" });
    expect(calls()).toEqual({ save: 1, find: 2, touch: 1 });
    expect(rows.get(token)).toMatchObject({
      updatedAt: NOW + 4 * HOUR,
      expiresAt: NOW + 12 * HOUR,
    });
    expect(due.res.headers.getSetCookie()).toEqual([]);

    const readonly = { req: request({ cookie: `__Host-unauth=${token}` }).req };
    vi.setSystemTime(NOW + 8 * HOUR + 1);
    expect((await sessions.use(readonly).record).data).toEqual({ userId: "u1" });
    expect(calls()).toEqual({ save: 1, find: 3, touch: 2 });
    expect(rows.get(token)?.expiresAt).toBe(NOW + 16 * HOUR + 1);
  });

  it("an idle extension never passes the absolute end", async () => {
    const { store, rows } = counted();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "10h", idle: "8h" });
    const token = await sessions.issue({ userId: "u1" });
    expect(rows.get(token)?.expiresAt).toBe(NOW + 8 * HOUR);
    vi.setSystemTime(NOW + 4 * HOUR);
    await sessions.use(request({ cookie: `__Host-unauth=${token}` })).record;
    expect(rows.get(token)?.expiresAt).toBe(NOW + 10 * HOUR);
    vi.setSystemTime(NOW + 10 * HOUR);
    const session = sessions.use(request({ cookie: `__Host-unauth=${token}` }));
    expect((await session.record).data).toBeUndefined();
    expect(session.error?.cause).toEqual({ reason: "expired" });
  });

  it("an expired session: data undefined, error expired, cookie expired, record left to the store", async () => {
    const { store, rows, calls } = counted();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h" });
    const token = await sessions.issue({ userId: "u1" });
    vi.setSystemTime(NOW + HOUR);
    const event = request({ cookie: `__Host-unauth=${token}` });
    const session = sessions.use(event);
    expect((await session.record).data).toBeUndefined();
    expect(isUnauthError(session.error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
    expect(session.error?.cause).toEqual({ reason: "expired" });
    expect(session.error?.status).toBe(401);
    expect(cookieLine(event)).toContain("Max-Age=0");
    expect(session.token).toBe(token);
    expect(rows.size).toBe(1);
    expect(calls()).toEqual({ save: 1, find: 1 });
  });

  it("an unknown token: data undefined, error unknown, the cookie left as it is", async () => {
    const { store } = counted();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h" });
    const event = request({ cookie: `__Host-unauth=${"A".repeat(43)}` });
    const session = sessions.use(event);
    expect((await session.record).data).toBeUndefined();
    expect(session.error?.cause).toEqual({ reason: "unknown" });
    expect(event.res.headers.getSetCookie()).toEqual([]);
    expect((await session.update({ userId: "u2" }))?.data).toEqual({ userId: "u2" });
    expect(session.error).toBeUndefined();
    expect(cookieValue(cookieLine(event))).toBe(session.token);
  });

  it("is read-only without a response", async () => {
    const { store } = counted();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h" });
    const token = await sessions.issue({ userId: "u1" });
    const session = sessions.use({ req: request({ cookie: `__Host-unauth=${token}` }).req });
    expect((await session.record).data).toEqual({ userId: "u1" });
    const thrown = await session.update({ name: "x" }).catch((error: unknown) => error);
    expect(isUnauthError(thrown, "ERR_SESSION_READONLY_EVENT")).toBe(true);
    expect(isUnauthError(thrown) && thrown.status).toBe(500);
  });

  it("clear removes the session without a read and expires the cookie", async () => {
    const { store, rows, calls } = counted();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h" });
    const token = await sessions.issue({ userId: "u1" });
    const event = request({ cookie: `__Host-unauth=${token}` });
    const session = sessions.use(event);
    expect(await session.clear()).toEqual({
      id: undefined,
      createdAt: undefined,
      updatedAt: undefined,
      expiresAt: undefined,
      data: undefined,
    });
    expect(calls()).toEqual({ save: 1, delete: 1 });
    expect(rows.size).toBe(0);
    expect(session.token).toBeUndefined();
    expect((await session.record).data).toBeUndefined();
    expect(session.error).toBeUndefined();
    expect(cookieLine(event)).toContain("Max-Age=0");
    expect(calls()).toEqual({ save: 1, delete: 1 });

    expect((await session.update({ userId: "u2" }))?.data).toEqual({ userId: "u2" });
    expect(session.token).not.toBe(token);
    expect(cookieValue(cookieLine(event))).toBe(session.token);
    expect(event.res.headers.getSetCookie()).toHaveLength(1);
  });

  it("rotate moves the session under a new token in one rekey: id and createdAt stay, the absolute end stays", async () => {
    const { store, rows, calls } = counted();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "30D", idle: "7D" });
    const token = await sessions.issue({ userId: "u1" });
    const id = rows.get(token)?.id;
    vi.setSystemTime(NOW + DAY);
    const event = request({ cookie: `__Host-unauth=${token}` });
    const session = sessions.use(event);
    await session.record;
    const rotated = await session.rotate();
    const next = session.token!;
    expect(next).not.toBe(token);
    expect(rotated).toEqual({
      id,
      createdAt: NOW,
      updatedAt: NOW + DAY,
      expiresAt: NOW + 8 * DAY,
      data: { userId: "u1" },
    });
    expect(calls()).toEqual({ save: 1, find: 1, rekey: 1 });
    expect([...rows.keys()]).toEqual([next]);
    expect(rows.get(next)).toEqual({
      id,
      createdAt: NOW,
      updatedAt: NOW + DAY,
      expiresAt: NOW + 8 * DAY,
      data: { userId: "u1" },
    });
    expect(cookieValue(cookieLine(event))).toBe(next);
    expect(cookieLine(event)).toContain(new Date(NOW + 30 * DAY).toUTCString());
    expect((await session.record).data).toEqual({ userId: "u1" });
    expect(calls()).toEqual({ save: 1, find: 1, rekey: 1 });
    const old = sessions.use(request({ cookie: `__Host-unauth=${token}` }));
    expect((await old.record).data).toBeUndefined();
    expect(old.error?.cause).toEqual({ reason: "unknown" });
  });

  it("rotate without a session, or on one gone meanwhile, throws ERR_SESSION_NONE", async () => {
    const { store, rows } = counted();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h" });
    const none = sessions.use(request());
    const thrown = await none.rotate().catch((error: unknown) => error);
    expect(isUnauthError(thrown, "ERR_SESSION_NONE")).toBe(true);

    const token = await sessions.issue({ userId: "u1" });
    const session = sessions.use(request({ cookie: `__Host-unauth=${token}` }));
    await session.record;
    rows.clear();
    const gone = await session.rotate().catch((error: unknown) => error);
    expect(isUnauthError(gone, "ERR_SESSION_NONE")).toBe(true);
    expect((await session.record).data).toBeUndefined();
  });

  it("session header: a bearer is read, writes reach the store alone, clear revokes it", async () => {
    const { store, rows } = counted();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h", sessionHeader: true });
    const start = request();
    await sessions.use(start).update({ userId: "u1" });
    const token = cookieValue(cookieLine(start));

    const api = request({ headers: { "x-unauth-session": `Bearer ${token}` } });
    const session = sessions.use(api);
    expect(session.source).toBe("header");
    expect((await session.record).data).toEqual({ userId: "u1" });
    await session.update({ name: "n" });
    expect(api.res.headers.getSetCookie()).toEqual([]);
    expect(rows.get(token)?.data).toEqual({ userId: "u1", name: "n" });

    const before = session.token;
    await session.rotate();
    expect(api.res.headers.getSetCookie()).toEqual([]);
    expect(session.token).not.toBe(before);
    await session.clear();
    expect(rows.size).toBe(0);
    expect(api.res.headers.getSetCookie()).toEqual([]);
  });

  it("no cookie: tokens in hand and headers alone; a request event has nothing to read", async () => {
    const { store } = counted();
    const handed = defineOpaqueSession<Data>({ store, maxAge: "1h", cookie: false });
    const token = await handed.issue({ userId: "u1" });
    const session = handed.use({ token });
    expect(session.source).toBe("token");
    expect((await session.record).data).toEqual({ userId: "u1" });
    expect(() => handed.use(request())).toThrow(/token source/);

    const bearer = defineOpaqueSession<Data>({
      store,
      maxAge: "1h",
      cookie: false,
      sessionHeader: "authorization",
    });
    const event = request();
    const api = bearer.use(event);
    expect(api.source).toBe("header");
    expect((await api.update({ userId: "u2" }))?.data).toEqual({ userId: "u2" });
    expect(event.res.headers.getSetCookie()).toEqual([]);
    const next = request({ headers: { authorization: `Bearer ${api.token}` } });
    expect((await bearer.use(next).record).data).toEqual({ userId: "u2" });
  });

  it("session header without a token: error header before any read, the cookie untouched", async () => {
    const { store, calls } = counted();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h", sessionHeader: true });
    const event = request({ headers: { "x-unauth-session": "not a token" } });
    const session = sessions.use(event);
    expect(session.token).toBeUndefined();
    expect(session.error?.cause).toEqual({ reason: "header", header: "x-unauth-session" });
    expect((await session.record).data).toBeUndefined();
    expect(calls()).toEqual({});
    expect(event.res.headers.getSetCookie()).toEqual([]);
  });

  it("asks a store factory for the store at every operation, with the request's event", async () => {
    const before = counted();
    const after = counted();
    const seen: unknown[] = [];
    const sessions = defineOpaqueSession<Data>({
      store: (event) => {
        seen.push(event);
        return event && "res" in event && event.res?.headers.has("x-tx")
          ? after.store
          : before.store;
      },
      maxAge: "1h",
    });
    const token = await sessions.issue({ userId: "u1" });
    expect(seen).toEqual([undefined]);

    const event = request({ cookie: `__Host-unauth=${token}` });
    const session = sessions.use(event);
    expect((await session.record).data).toEqual({ userId: "u1" });
    expect(seen.at(-1)).toBe(event);
    event.res.headers.set("x-tx", "1");
    await session.update({ name: "in tx" });
    expect(before.rows.get(token)?.data).toEqual({ userId: "u1" });
    expect(after.rows.get(token)?.data).toEqual({ userId: "u1", name: "in tx" });
  });

  it("runs over a framework driver of its own", async () => {
    const { store } = counted();
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
    await sessions.use(first).update({ userId: "u1" });
    expect(first.written["__Host-unauth"]).toBe(sessions.use(first).token);
    const second: AppEvent = {
      cookies: { "__Host-unauth": first.written["__Host-unauth"]! },
      written: {},
      bag: {},
    };
    expect((await sessions.use(second).record).data).toEqual({ userId: "u1" });
  });

  it("refuses an event the driver does not take, and a name another kind of session bound", async () => {
    const { store } = counted();
    const sessions = defineOpaqueSession<Data>({ store, maxAge: "1h" });
    // @ts-expect-error -- neither a request event nor a token
    expect(() => sessions.use({})).toThrow(/^\[unauth\/session\]/);
    const key: JWK_oct<"HS256"> = await generateJWK("HS256");
    const jws = defineJWSSession({ key, name: "__Host-unauth" });
    const event = request();
    await jws.use(event);
    const thrown = caught(() => sessions.use(event));
    expect(isUnauthError(thrown, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    expect(isUnauthError(thrown) && thrown.message).toMatch(/JWS/);
  });

  it("mints ids with the config's generator, refusing an empty one", async () => {
    const { store, rows } = counted();
    let n = 0;
    const sessions = defineOpaqueSession<Data>({ store, generateId: () => `sess_${++n}` });
    const token = await sessions.issue({ userId: "u1" });
    expect(rows.get(token)?.id).toBe("sess_1");
    const event = request();
    expect((await sessions.use(event).update({ userId: "u2" }))?.id).toBe("sess_2");

    const broken = defineOpaqueSession<Data>({ store, generateId: () => "" });
    const thrown = await broken.issue({ userId: "u1" }).catch((error: unknown) => error);
    expect(isUnauthError(thrown, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    expect(isUnauthError(thrown) && thrown.message).toMatch(/"generateId"/);
  });

  it("refuses a config that cannot work", () => {
    const { store } = counted();
    const refused = (config: OpaqueSessionConfig<Data>) => {
      try {
        defineOpaqueSession(config);
      } catch (error) {
        return isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID") ? error.message : error;
      }
      return undefined;
    };
    expect(refused({ store, maxAge: "0s" })).toMatch(/^\[unauth\/session\] A session's "maxAge"/);
    expect(refused({ store, idle: "-1" })).toMatch(/"idle"/);
    expect(refused({ store, bytes: 8 })).toMatch(/16 to 384/);
    expect(refused({ store, cookie: { secure: false } })).toMatch(/__Host-/);
    expect(refused({ store, sessionHeader: "bad header" })).toMatch(/sessionHeader/);
    expect(refused({ store, name: "session", cookie: { secure: false } })).toBeUndefined();
  });

  it("works over kvSessionStore", async () => {
    const entries = new Map<string, { value: unknown; ttl?: number }>();
    const driver: CacheDriver = {
      // oxlint-disable-next-line typescript/no-unnecessary-type-parameters -- `CacheDriver.get` types the value at its call site
      get: <T>(key: string) =>
        entries.has(key) ? (structuredClone(entries.get(key)!.value) as T) : null,
      set: (key, value, options) => {
        if (value === null) entries.delete(key);
        else entries.set(key, { value: structuredClone(value), ttl: options?.ttl });
      },
    };
    const sessions = defineOpaqueSession<Data>({
      store: kvSessionStore(driver, { prefix: "s:" }),
      maxAge: "1h",
    });
    const event = request();
    await sessions.use(event).update({ userId: "u1" });
    const token = cookieValue(cookieLine(event));
    expect(entries.get(`s:${token}`)?.ttl).toBe(3600);
    expect((await sessions.use(request({ cookie: `__Host-unauth=${token}` })).record).data).toEqual(
      {
        userId: "u1",
      },
    );
  });

  it("types the handle", async () => {
    const { store } = counted();
    const sessions = defineOpaqueSession<Data>({ store });
    const session = sessions.use(request());
    expectTypeOf(session).toEqualTypeOf<OpaqueSession<Data>>();
    expectTypeOf(session.token).toEqualTypeOf<string | undefined>();
    expectTypeOf(session.record).toEqualTypeOf<
      Promise<OpaqueSessionRecord<Data> | OpaqueSessionNone>
    >();
    const { id, data, expiresAt } = await session.record;
    if (id === undefined) {
      expectTypeOf(data).toEqualTypeOf<undefined>();
    } else {
      expectTypeOf(data).toEqualTypeOf<Data>();
      expectTypeOf(expiresAt).toEqualTypeOf<number | undefined>();
    }
    expectTypeOf(await session.update({ userId: "u" })).toEqualTypeOf<
      OpaqueSessionRecord<Data> | undefined
    >();
    expectTypeOf(await session.rotate()).toEqualTypeOf<OpaqueSessionRecord<Data>>();
    expectTypeOf(await session.clear()).toEqualTypeOf<OpaqueSessionNone>();
    expectTypeOf<Parameters<typeof sessions.use>[0]>().toEqualTypeOf<WebSessionEvent>();
    type AppEvent = { req: Request; context: { tx?: { name: string } } };
    defineOpaqueSession<Data, AppEvent>({
      store: (event) => {
        expectTypeOf(event).toEqualTypeOf<AppEvent | undefined>();
        return store;
      },
    });
  });
});

/** A one-statement store over a map, counting what the session asks of it. */
function counted() {
  const rows = new Map<string, OpaqueSessionRecord<Data>>();
  const count: Record<string, number> = {};
  const tick = (verb: string) => {
    count[verb] = (count[verb] ?? 0) + 1;
  };
  const store: OpaqueSessionStore<Data> = {
    find: (token) => {
      tick("find");
      const row = rows.get(token);
      return row ? structuredClone(row) : null;
    },
    save: (token, record) => {
      tick("save");
      rows.set(token, structuredClone(record));
    },
    touch: (token, times) => {
      tick("touch");
      const row = rows.get(token);
      if (!row) return false;
      rows.set(token, { ...row, ...times });
      return true;
    },
    rekey: (from, to, times) => {
      tick("rekey");
      const row = rows.get(from);
      if (!row) return false;
      rows.delete(from);
      rows.set(to, { ...row, ...times });
      return true;
    },
    delete: (token) => {
      tick("delete");
      rows.delete(token);
    },
  };
  return { store, rows, calls: () => ({ ...count }) };
}

function caught(run: () => unknown): unknown {
  try {
    run();
  } catch (error) {
    return error;
  }
  return undefined;
}

function request(options?: { cookie?: string; headers?: Record<string, string> }) {
  const headers = new Headers(options?.headers);
  if (options?.cookie) headers.set("cookie", options.cookie);
  return {
    req: new Request("https://app.test/", { headers }),
    res: { headers: new Headers(), errHeaders: new Headers() },
  };
}

function cookieLine(event: ReturnType<typeof request>): string {
  const line = event.res.headers.getSetCookie().find((set) => set.startsWith("__Host-unauth="));
  if (!line) throw new Error("no session cookie");
  return line;
}

function cookieValue(line: string): string {
  return line.slice(line.indexOf("=") + 1, line.indexOf(";"));
}
