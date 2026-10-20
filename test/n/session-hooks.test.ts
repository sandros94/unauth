import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { type JWK_oct, generateJWK } from "unjwt/session";

import {
  type AuthSessionDefinition,
  type AuthSessionManager,
  defineAuthSession,
} from "../../src/n/index.ts";
import { isExpired, requestWith, setCookieLine } from "./_session.ts";

interface User {
  userId: string;
  role?: string;
}

const T0 = Date.UTC(2026, 9, 1, 12);
const MINUTE = 60_000;

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

async function signInToken(auth: AuthSessionDefinition<User>, data: User): Promise<string> {
  const session = await auth.use({ token: undefined });
  await session.authenticate(data);
  return session.token!;
}

async function signInHeaders(auth: AuthSessionDefinition<User>, data: User): Promise<Headers> {
  const headers = new Headers();
  const session = await auth.use({ req: requestWith(), res: { headers } });
  await session.authenticate(data);
  return headers;
}

describe("isRevoked", () => {
  it("clears a revoked session read from a request and expires its cookie", async () => {
    const onRead = vi.fn();
    const onSignOut = vi.fn();
    const seen: unknown[] = [];
    const isRevoked = vi.fn(({ session }: { session: { data: User } }) => {
      seen.push(session.data.userId);
      return true;
    });
    const auth = defineAuthSession<User>({ key, hooks: { isRevoked, onRead, onSignOut } });
    const login = await signInHeaders(auth, { userId: "u1" });

    const request = requestWith(login);
    const headers = new Headers();
    const session = await auth.use({ req: request, res: { headers } });

    expect(session.id).toBeUndefined();
    expect(session.data).toEqual({});
    expect(isExpired(setCookieLine(headers, "__Host-unauth")!)).toBe(true);
    expect(onRead).not.toHaveBeenCalled();
    expect(isRevoked).toHaveBeenCalledOnce();
    const [args] = isRevoked.mock.calls[0] as unknown as [{ context: unknown; session: object }];
    expect(args.context).toEqual({ req: request, res: { headers } });
    expect(seen).toEqual(["u1"]);
    expect(args.session).toHaveProperty("authenticate");
    expect(onSignOut).toHaveBeenCalledOnce();
    expect(onSignOut.mock.calls[0]![0].oldSession.data.userId).toBe("u1");
    expect(onSignOut.mock.calls[0]![0].reason).toBe("revoked");
  });

  it("lets a session it keeps through to onRead", async () => {
    const onRead = vi.fn();
    const auth = defineAuthSession<User>({ key, hooks: { isRevoked: async () => false, onRead } });
    const token = await signInToken(auth, { userId: "u1" });

    const session = await auth.use({ token });

    expect(session.data.userId).toBe("u1");
    expect(onRead).toHaveBeenCalledOnce();
  });

  it("empties a revoked handed token", async () => {
    const auth = defineAuthSession<User>({ key, hooks: { isRevoked: () => true } });
    const token = await signInToken(auth, { userId: "u1" });

    const session = await auth.use({ token });

    expect(session.id).toBeUndefined();
    expect(session.token).toBeUndefined();
  });

  it("clears a revoked session on a read-only context without writing", async () => {
    const auth = defineAuthSession<User>({ key, hooks: { isRevoked: () => true } });
    const plain = defineAuthSession<User>({ key });
    const request = requestWith(await signInHeaders(plain, { userId: "u1" }));

    const first = await auth.use({ req: request });
    const retry = await auth.use({ req: request });

    expect(first.id).toBeUndefined();
    expect(first.data).toEqual({});
    expect(retry.id).toBeUndefined();
  });
});

describe("refresh", () => {
  it("is not consulted while the session does not roll", async () => {
    const refresh = vi.fn(() => undefined);
    const auth = defineAuthSession<User>({ key, maxAge: "1h", rolling: "15m", hooks: { refresh } });
    const token = await signInToken(auth, { userId: "u1" });

    vi.setSystemTime(T0 + 10 * MINUTE);
    await auth.use({ token });

    expect(refresh).not.toHaveBeenCalled();
  });

  it("keeps the rolled session when it returns undefined", async () => {
    const refresh = vi.fn(() => undefined);
    const auth = defineAuthSession<User>({ key, maxAge: "1h", rolling: "15m", hooks: { refresh } });
    const token = await signInToken(auth, { userId: "u1", role: "user" });

    vi.setSystemTime(T0 + 50 * MINUTE);
    const session = await auth.use({ token });

    expect(refresh).toHaveBeenCalledOnce();
    expect(session.token).not.toBe(token);
    expect(session.data).toEqual({ userId: "u1", role: "user", authenticatedAt: T0 });
  });

  it("merges what it returns into the reissued token", async () => {
    const auth = defineAuthSession<User>({
      key,
      maxAge: "1h",
      rolling: "15m",
      hooks: { refresh: () => ({ role: "admin", authenticatedAt: 1 }) as Partial<User> },
    });
    const token = await signInToken(auth, { userId: "u1", role: "user" });

    vi.setSystemTime(T0 + 50 * MINUTE);
    const session = await auth.use({ token });

    expect(session.data).toEqual({ userId: "u1", role: "admin", authenticatedAt: T0 });
    const opened = await auth.open(session.token!);
    expect(opened.data).toEqual({ userId: "u1", role: "admin", authenticatedAt: T0 });
    expect(opened.expiresAt).toBe(T0 + 50 * MINUTE + 60 * MINUTE);
  });

  it("writes the merged session over the rolled cookie", async () => {
    const auth = defineAuthSession<User>({
      key,
      maxAge: "1h",
      rolling: "15m",
      hooks: { refresh: () => ({ role: "admin" }) },
    });
    const login = await signInHeaders(auth, { userId: "u1", role: "user" });

    vi.setSystemTime(T0 + 50 * MINUTE);
    const headers = new Headers();
    await auth.use({ req: requestWith(login), res: { headers } });

    const lines = headers.getSetCookie().filter((line) => line.startsWith("__Host-unauth="));
    expect(lines).toHaveLength(1);
    const next = await auth.use({ req: requestWith(headers) });
    expect(next.data.role).toBe("admin");
  });

  it("clears the session when it returns false", async () => {
    const onSignOut = vi.fn();
    const auth = defineAuthSession<User>({
      key,
      maxAge: "1h",
      rolling: "15m",
      hooks: { refresh: async () => false as const, onSignOut },
    });
    const login = await signInHeaders(auth, { userId: "u1" });

    vi.setSystemTime(T0 + 50 * MINUTE);
    const headers = new Headers();
    const session = await auth.use({ req: requestWith(login), res: { headers } });

    expect(session.id).toBeUndefined();
    expect(isExpired(setCookieLine(headers, "__Host-unauth")!)).toBe(true);
    expect(onSignOut).toHaveBeenCalledOnce();
    expect(onSignOut.mock.calls[0]![0].reason).toBe("refresh");
  });

  it("receives the session and the context", async () => {
    const refresh = vi.fn((_args: { session: unknown; context: unknown }) => undefined);
    const auth = defineAuthSession<User>({ key, maxAge: "1h", rolling: true, hooks: { refresh } });
    const token = await signInToken(auth, { userId: "u1" });

    vi.setSystemTime(T0 + MINUTE);
    const context = { token };
    await auth.use(context);

    const args = refresh.mock.calls[0]![0] as {
      context: unknown;
      session: AuthSessionManager<User>;
    };
    expect(args.context).toBe(context);
    expect(args.session.data.userId).toBe("u1");
    expect(args.session.requireRecent).toBeTypeOf("function");
  });

  it("reports the roll before the merge to onUpdate, so session ids chain", async () => {
    const updates: { trigger: string; from: string | undefined; to: string }[] = [];
    const auth = defineAuthSession<User>({
      key,
      maxAge: "1h",
      rolling: "15m",
      hooks: {
        refresh: () => ({ role: "admin" }),
        onUpdate: ({ trigger, oldSession, session }) => {
          updates.push({ trigger, from: oldSession.id, to: session.id });
        },
      },
    });
    const token = await signInToken(auth, { userId: "u1" });
    const signedInId = updates[0]!.to;
    updates.length = 0;

    vi.setSystemTime(T0 + 50 * MINUTE);
    const session = await auth.use({ token });

    expect(updates.map((u) => u.trigger)).toEqual(["rolling", "update"]);
    expect(updates[0]!.from).toBe(signedInId);
    expect(updates[1]!.from).toBe(updates[0]!.to);
    expect(updates[1]!.to).toBe(session.id);
  });
});

describe("onSignIn / onSignOut", () => {
  it("onSignIn fires on authenticate() with the session and the context", async () => {
    const onSignIn = vi.fn();
    const onUpdate = vi.fn();
    const auth = defineAuthSession<User>({ key, hooks: { onSignIn, onUpdate } });
    const context = { token: undefined };
    const session = await auth.use(context);

    await session.update({ userId: "anon" });
    expect(onSignIn).not.toHaveBeenCalled();

    await session.authenticate({ userId: "u1" });
    expect(onSignIn).toHaveBeenCalledOnce();
    const args = onSignIn.mock.calls[0]![0];
    expect(args.context).toBe(context);
    expect(args.session.data).toEqual({ userId: "u1", authenticatedAt: T0 });
    expect(onUpdate).toHaveBeenCalledTimes(2);
  });

  it("onSignOut fires on clear() of an authenticated session only", async () => {
    const onSignOut = vi.fn();
    const onClear = vi.fn();
    const auth = defineAuthSession<User>({ key, hooks: { onSignOut, onClear } });

    const anonymous = await auth.use({ token: undefined });
    await anonymous.update({ userId: "anon" });
    await anonymous.clear();
    expect(onSignOut).not.toHaveBeenCalled();

    const session = await auth.use({ token: undefined });
    await session.authenticate({ userId: "u1" });
    const id = session.id;
    await session.clear();

    expect(onSignOut).toHaveBeenCalledOnce();
    expect(onSignOut.mock.calls[0]![0].oldSession.id).toBe(id);
    expect(onSignOut.mock.calls[0]![0].reason).toBe("clear");
    expect(onClear).toHaveBeenCalledTimes(2);
  });

  it("onSignOut tells revocation, a failed refresh and clear() apart on one definition", async () => {
    const reasons: string[] = [];
    let revoked = false;
    let gone = false;
    const auth = defineAuthSession<User>({
      key,
      maxAge: "1h",
      rolling: "15m",
      hooks: {
        isRevoked: () => revoked,
        refresh: () => (gone ? false : undefined),
        onSignOut: ({ reason }) => {
          reasons.push(reason);
        },
      },
    });
    const first = await signInToken(auth, { userId: "u1" });
    const second = await signInToken(auth, { userId: "u2" });

    revoked = true;
    await auth.use({ token: first });
    revoked = false;
    await (await auth.use({ token: second })).clear();
    const third = await signInToken(auth, { userId: "u3" });
    gone = true;
    vi.setSystemTime(T0 + 50 * MINUTE);
    await auth.use({ token: third });
    const fourth = await signInToken(auth, { userId: "u4" });
    await (await auth.use({ token: fourth })).clear();

    expect(reasons).toEqual(["revoked", "clear", "refresh", "clear"]);
  });
});

describe("unjwt hooks", () => {
  it("pass through unchanged", async () => {
    const onRead = vi.fn();
    const onUpdate = vi.fn();
    const onClear = vi.fn();
    const onExpire = vi.fn();
    const onError = vi.fn();
    const auth = defineAuthSession<User>({
      key,
      maxAge: "1h",
      rolling: false,
      hooks: { onRead, onUpdate, onClear, onExpire, onError },
    });
    const token = await signInToken(auth, { userId: "u1" });
    expect(onUpdate.mock.calls[0]![0].trigger).toBe("update");

    const session = await auth.use({ token });
    expect(onRead).toHaveBeenCalledOnce();
    expect(onRead.mock.calls[0]![0].session.data.userId).toBe("u1");
    await session.clear();
    expect(onClear).toHaveBeenCalledOnce();

    await auth.use({ token: "not-a-token" });
    expect(onError).toHaveBeenCalledOnce();

    vi.setSystemTime(T0 + 61 * MINUTE);
    await auth.use({ token });
    expect(onExpire).toHaveBeenCalledOnce();
  });
});
