import { afterEach, beforeAll, beforeEach, describe, expect, expectTypeOf, it, vi } from "vitest";
import {
  type JWK_oct,
  defineJWSSession,
  defineSessionDriver,
  defineJWESession,
  generateJWK,
} from "unjwt/session";

import {
  type AuthSessionDefinition,
  type AuthSessionManager,
  type AuthenticatedData,
  defineAuthSession,
  isUnauthError,
  optionalSession,
  requireSession,
} from "../../src/n/index.ts";
import { requestWith, setCookieLine } from "./_session.ts";

interface User {
  userId: string;
  role?: string;
}

const T0 = Date.UTC(2026, 9, 1, 12);
const DAY = 86_400_000;

let key: JWK_oct<"A256GCM">;

beforeAll(async () => {
  key = await generateJWK("A256GCM");
});

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"], now: T0 });
});

afterEach(() => {
  vi.useRealTimers();
});

/** Signs a user in on a fresh request; returns the response headers carrying the session cookie. */
async function signedIn(auth: AuthSessionDefinition<User>, data: User): Promise<Headers> {
  const headers = new Headers();
  const session = await auth.use({ request: requestWith(), headers });
  await session.authenticate(data);
  return headers;
}

describe("defineAuthSession defaults", () => {
  it("names the cookie __Host-unauth with httpOnly, secure, lax attributes", async () => {
    const auth = defineAuthSession<User>({ key });
    const headers = await signedIn(auth, { userId: "u1" });

    const line = setCookieLine(headers, "__Host-unauth");
    expect(line).toBeDefined();
    expect(line).toMatch(/; HttpOnly/i);
    expect(line).toMatch(/; Secure/i);
    expect(line).toMatch(/; SameSite=Lax/i);
    expect(line).toMatch(/; Path=\//i);
  });

  it("drops the prefix when cookies are not secure", async () => {
    const auth = defineAuthSession<User>({ key, cookie: { secure: false } });
    const headers = await signedIn(auth, { userId: "u1" });

    expect(setCookieLine(headers, "unauth")).toBeDefined();
  });

  it("uses __Secure- when a domain rules out __Host-", async () => {
    const auth = defineAuthSession<User>({ key, cookie: { domain: "app.test" } });
    const headers = await signedIn(auth, { userId: "u1" });

    expect(setCookieLine(headers, "__Secure-unauth")).toBeDefined();
  });

  it("keeps an explicit name", async () => {
    const auth = defineAuthSession<User>({ key, name: "sid", cookie: { secure: false } });
    const headers = await signedIn(auth, { userId: "u1" });

    expect(setCookieLine(headers, "sid")).toBeDefined();
  });

  it("keeps the session cookie httpOnly on a JWS session", async () => {
    const signingKey = await generateJWK("HS256");
    const auth = defineAuthSession<User>({ key: signingKey }, { define: defineJWSSession });
    const headers = await signedIn(auth, { userId: "u1" });

    expect(setCookieLine(headers, "__Host-unauth")).toMatch(/; HttpOnly/i);
  });

  it("expires after 7 days", async () => {
    const auth = defineAuthSession<User>({ key });
    const session = await auth.use({ token: undefined });
    await session.authenticate({ userId: "u1" });

    expect(session.expiresAt - session.createdAt).toBe(7 * DAY);
  });

  it("rolls once less than a quarter of maxAge remains", async () => {
    const auth = defineAuthSession<User>({ key, maxAge: "4D" });
    const first = await auth.use({ token: undefined });
    await first.authenticate({ userId: "u1" });
    const token = first.token;

    vi.setSystemTime(T0 + 2.9 * DAY);
    const early = await auth.use({ token });
    expect(early.token).toBe(token);

    vi.setSystemTime(T0 + 3.1 * DAY);
    const late = await auth.use({ token });
    expect(late.token).not.toBe(token);
    expect(late.expiresAt).toBe(T0 + 3.1 * DAY + 4 * DAY);
  });

  it("never rolls with rolling: false", async () => {
    const auth = defineAuthSession<User>({ key, maxAge: "4D", rolling: false });
    const first = await auth.use({ token: undefined });
    await first.authenticate({ userId: "u1" });
    const token = first.token;

    vi.setSystemTime(T0 + 3.9 * DAY);
    const late = await auth.use({ token });
    expect(late.token).toBe(token);
  });
});

describe("authenticatedAt", () => {
  it("is set by authenticate() with a new session id", async () => {
    const auth = defineAuthSession<User>({ key });
    const session = await auth.use({ token: undefined });
    await session.update({ userId: "anon" });
    const anonymousId = session.id;

    await session.authenticate({ userId: "u1" });

    expect(session.data).toEqual({ userId: "u1", authenticatedAt: T0 });
    expect(session.id).toBeTypeOf("string");
    expect(session.id).not.toBe(anonymousId);
  });

  it("travels in the token across requests", async () => {
    const auth = defineAuthSession<User>({ key });
    const headers = await signedIn(auth, { userId: "u1" });

    const next = await auth.use({ request: requestWith(headers), headers: new Headers() });
    expect(next.data.authenticatedAt).toBe(T0);
  });

  it("survives update() and cannot be set through it", async () => {
    const auth = defineAuthSession<User>({ key });
    const session = await auth.use({ token: undefined });
    await session.authenticate({ userId: "u1" });

    vi.setSystemTime(T0 + 1000);
    await session.update({ role: "admin", authenticatedAt: T0 + 1000 } as Partial<User>);
    await session.update(() => ({ authenticatedAt: T0 + 2000 }) as Partial<User>);

    expect(session.data).toEqual({ userId: "u1", role: "admin", authenticatedAt: T0 });
    const opened = await auth.open(session.token!);
    expect(opened.data.authenticatedAt).toBe(T0);
  });

  it("cannot be forged through the live data handed to a function update", async () => {
    const auth = defineAuthSession<User>({ key });
    const session = await auth.use({ token: undefined });
    await session.update({ userId: "anon" });

    await session.update((old) => {
      (old as Record<string, unknown>).authenticatedAt = T0;
      return { role: "x" };
    });

    expect(session.data).toEqual({ userId: "anon", role: "x" });
    expect((await auth.open(session.token!)).data).toEqual({ userId: "anon", role: "x" });
  });

  it("keeps a real authenticatedAt through a function update that tries to change it", async () => {
    const auth = defineAuthSession<User>({ key });
    const session = await auth.use({ token: undefined });
    await session.authenticate({ userId: "u1" });

    await session.update((old) => {
      (old as Record<string, unknown>).authenticatedAt = 1;
      return {};
    });

    expect(session.data.authenticatedAt).toBe(T0);
  });

  it("cannot be forged by writing to session.data", async () => {
    const auth = defineAuthSession<User>({ key });
    const session = await auth.use({ token: undefined });
    await session.update({ userId: "anon" });

    expect(() => {
      (session.data as Record<string, unknown>).authenticatedAt = T0;
    }).toThrow(TypeError);
    await session.update({});

    expect(session.data.authenticatedAt).toBeUndefined();
    expect(Object.isFrozen(session.data)).toBe(true);
  });

  it("still moves forward with authenticate() after updates", async () => {
    const auth = defineAuthSession<User>({ key });
    const session = await auth.use({ token: undefined });
    await session.authenticate({ userId: "u1" });
    await session.update({ role: "admin" });

    vi.setSystemTime(T0 + 5000);
    await session.authenticate({ userId: "u1" });

    expect(session.data).toEqual({ userId: "u1", role: "admin", authenticatedAt: T0 + 5000 });
  });

  it("survives rolling", async () => {
    const auth = defineAuthSession<User>({ key, maxAge: "1h", rolling: true });
    const session = await auth.use({ token: undefined });
    await session.authenticate({ userId: "u1" });

    vi.setSystemTime(T0 + 60_000);
    const rolled = await auth.use({ token: session.token });

    expect(rolled.token).not.toBe(session.token);
    expect(rolled.data.authenticatedAt).toBe(T0);
  });

  it("is gone after clear()", async () => {
    const auth = defineAuthSession<User>({ key });
    const session = await auth.use({ token: undefined });
    await session.authenticate({ userId: "u1" });
    await session.clear();

    expect(session.id).toBeUndefined();
    expect(session.data.authenticatedAt).toBeUndefined();
  });

  it("is not minted by issue()", async () => {
    const auth = defineAuthSession<User>({ key });
    const token = await auth.issue({ userId: "u1", authenticatedAt: T0 } as Partial<User>);

    const opened = await auth.open(token);
    expect(opened.data).toEqual({ userId: "u1" });
  });

  it("moves forward on every authenticate(), even within one millisecond", async () => {
    const auth = defineAuthSession<User>({ key });
    const session = await auth.use({ token: undefined });
    await session.authenticate({ userId: "u1" });
    await session.authenticate({ userId: "u1" });

    expect(session.data.authenticatedAt).toBeGreaterThan(T0);
  });
});

describe("requireRecent", () => {
  it("passes within maxAge", async () => {
    const auth = defineAuthSession<User>({ key });
    const session = await auth.use({ token: undefined });
    await session.authenticate({ userId: "u1" });

    vi.setSystemTime(T0 + 5 * 60_000);
    expect(() => session.requireRecent("5m")).not.toThrow();
  });

  it("throws ERR_AUTHN_REAUTH_REQUIRED (401) when older", async () => {
    const auth = defineAuthSession<User>({ key });
    const session = await auth.use({ token: undefined });
    await session.authenticate({ userId: "u1" });

    vi.setSystemTime(T0 + 5 * 60_000 + 1);
    const error = catchError(() => session.requireRecent("5m"));

    expect(isUnauthError(error, "ERR_AUTHN_REAUTH_REQUIRED")).toBe(true);
    if (!isUnauthError(error, "ERR_AUTHN_REAUTH_REQUIRED")) return;
    expect(error.status).toBe(401);
    expect(error.cause).toEqual({ authenticatedAt: T0 });
    expect(error.message).toMatch(/^\[unauth\/n\] /);
  });

  it("throws ERR_AUTHN_UNAUTHENTICATED (401) without an authenticated session", async () => {
    const auth = defineAuthSession<User>({ key });
    const empty = await auth.use({ token: undefined });
    const anonymous = await auth.use({ token: undefined });
    await anonymous.update({ userId: "anon" });

    for (const session of [empty, anonymous]) {
      const error = catchError(() => session.requireRecent("1h"));
      expect(isUnauthError(error, "ERR_AUTHN_UNAUTHENTICATED")).toBe(true);
      expect(isUnauthError(error) && error.status).toBe(401);
    }
  });
});

describe("requireSession / optionalSession", () => {
  it("return the data of an authenticated session", async () => {
    const auth = defineAuthSession<User>({ key });
    const session = await auth.use({ token: undefined });
    await session.authenticate({ userId: "u1", role: "admin" });

    expect(requireSession(session)).toEqual({ userId: "u1", role: "admin", authenticatedAt: T0 });
    expect(optionalSession(session)).toEqual(requireSession(session));
  });

  it("treat an empty or never-authenticated session as signed out", async () => {
    const auth = defineAuthSession<User>({ key });
    const empty = await auth.use({ token: undefined });
    const anonymous = await auth.use({ token: undefined });
    await anonymous.update({ userId: "anon" });

    for (const session of [empty, anonymous]) {
      const error = catchError(() => requireSession(session));
      expect(isUnauthError(error, "ERR_AUTHN_UNAUTHENTICATED")).toBe(true);
      expect(isUnauthError(error) && error.status).toBe(401);
      expect(optionalSession(session)).toBeUndefined();
    }
  });
});

describe("define", () => {
  it("runs over a custom driver", async () => {
    interface Ctx {
      cookies: Map<string, string>;
      locals: Record<string, unknown>;
    }
    const driver = defineSessionDriver<Ctx>({
      prefix: "[test]",
      state: (ctx) => ctx.locals,
      header: () => undefined,
      cookies: (ctx) => ({
        read: (name) => ctx.cookies.get(name),
        write: (name, value) => void ctx.cookies.set(name, value),
      }),
    });
    const auth = defineAuthSession<User, Ctx>(
      { key, cookie: { secure: false } },
      { define: (config) => defineJWESession(config, { driver }) },
    );

    const ctx: Ctx = { cookies: new Map(), locals: {} };
    const session = await auth.use(ctx);
    await session.authenticate({ userId: "u1" });

    expect(ctx.cookies.get("unauth")).toBe(session.token);
    const next = await auth.use({ cookies: ctx.cookies, locals: {} });
    expect(requireSession(next).userId).toBe("u1");
  });
});

describe("types", () => {
  it("name the definition, the manager and the guarded data", () => {
    const auth = defineAuthSession<User>({ key: {} as JWK_oct<"A256GCM"> });

    expectTypeOf(auth).toEqualTypeOf<AuthSessionDefinition<User>>();
    expectTypeOf(auth.use).returns.resolves.toEqualTypeOf<AuthSessionManager<User>>();
    expectTypeOf(requireSession<User>).returns.toEqualTypeOf<AuthenticatedData<User>>();
    expectTypeOf<AuthenticatedData<User>["authenticatedAt"]>().toEqualTypeOf<number>();
    expectTypeOf<AuthSessionManager<User>["expiresAt"]>().toEqualTypeOf<number>();
    expectTypeOf<AuthSessionManager<User>["update"]>()
      .parameter(0)
      .exclude<undefined>()
      .exclude<(...args: never[]) => unknown>()
      .not.toHaveProperty("authenticatedAt");
  });
});

function catchError(run: () => unknown): unknown {
  try {
    run();
  } catch (error) {
    return error;
  }
  throw new Error("expected a throw");
}
