import { type RequestEvent, createError, deleteCookie, getCookie, setCookie } from "nuxt/server";
import { createOpaqueToken, hashOpaqueToken } from "unauth/n";

const COOKIE = import.meta.dev ? "session" : "__Host-session";
const MAX_AGE = 60 * 60;
const ROLLING = 15 * 60;

export async function createSession(
  event: RequestEvent,
  options: { userId: string },
): Promise<AuthSession> {
  const db = await useSessions();
  const current = getCookie(event, COOKIE);
  if (current) {
    await db.sql`DELETE FROM sessions WHERE token_hash = ${await hashOpaqueToken(current)}`;
  }
  const { token, hash } = await createOpaqueToken();
  const now = Date.now();
  const expiresAt = now + MAX_AGE * 1000;
  await db.sql`INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_seen_at) VALUES (${hash}, ${options.userId}, ${now}, ${expiresAt}, ${now})`;
  writeCookie(event, token);
  return { userId: options.userId, createdAt: now, expiresAt };
}

export async function useAuthSession(event: RequestEvent): Promise<AuthSession | undefined> {
  const token = getCookie(event, COOKIE);
  if (!token) return undefined;
  const db = await useSessions();
  const hash = await hashOpaqueToken(token);
  const { rows } = await db.sql<{
    rows: SessionRow[];
  }>`SELECT user_id, created_at, expires_at, last_seen_at FROM sessions WHERE token_hash = ${hash}`;
  const row = rows[0];
  const now = Date.now();
  if (row === undefined || row.expires_at <= now) {
    if (row) await db.sql`DELETE FROM sessions WHERE token_hash = ${hash}`;
    deleteCookie(event, COOKIE, cookieOptions());
    return undefined;
  }
  let expiresAt = row.expires_at;
  if (now - row.last_seen_at >= ROLLING * 1000) {
    expiresAt = now + MAX_AGE * 1000;
    await db.sql`UPDATE sessions SET expires_at = ${expiresAt}, last_seen_at = ${now} WHERE token_hash = ${hash}`;
    writeCookie(event, token);
  }
  return { userId: row.user_id, createdAt: row.created_at, expiresAt };
}

export async function requireAuthSession(event: RequestEvent): Promise<AuthSession> {
  const session = await useAuthSession(event);
  if (!session) throw createError({ statusCode: 401, message: "Sign in first" });
  return session;
}

export async function terminateSession(event: RequestEvent): Promise<void> {
  const token = getCookie(event, COOKIE);
  if (token) {
    const db = await useSessions();
    await db.sql`DELETE FROM sessions WHERE token_hash = ${await hashOpaqueToken(token)}`;
  }
  deleteCookie(event, COOKIE, cookieOptions());
}

export async function revokeSessions(userId: string): Promise<void> {
  const db = await useSessions();
  await db.sql`DELETE FROM sessions WHERE user_id = ${userId}`;
}

interface SessionRow {
  user_id: string;
  created_at: number;
  expires_at: number;
  last_seen_at: number;
}

let sessions: ReturnType<typeof setUp> | undefined;

function useSessions(): ReturnType<typeof setUp> {
  return (sessions ??= setUp());
}

async function setUp() {
  const db = useDatabase();
  await db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      last_seen_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sessions_user_id ON sessions (user_id);
  `);
  return db;
}

function cookieOptions() {
  return { httpOnly: true, sameSite: "lax", secure: !import.meta.dev, path: "/" } as const;
}

function writeCookie(event: RequestEvent, token: string) {
  setCookie(event, COOKIE, token, { ...cookieOptions(), maxAge: MAX_AGE });
}
