import { createError } from "nuxt/server";
import {
  type OpaqueSessionManager,
  type OpaqueSessionRecord,
  type SessionRequestEvent,
  defineOpaqueSession,
} from "unauth/session";
import type { CacheDriver } from "unauth/utils";

const definition = defineOpaqueSession<SessionData>({
  store: sqliteStore(),
  maxAge: "1h",
  rolling: "15m",
});

export function useAuthSession(
  event: SessionRequestEvent,
): Promise<OpaqueSessionManager<SessionData>> {
  return definition.use(event);
}

export async function requireAuthSession(
  event: SessionRequestEvent,
): Promise<OpaqueSessionManager<SessionData>> {
  const session = await useAuthSession(event);
  if (!session.id) throw createError({ statusCode: 401, message: "Sign in first" });
  return session;
}

export interface SessionRow {
  id: string;
  family: string;
  createdAt: number;
  updatedAt: number;
  expiresAt: number;
}

export async function listSessions(userId: string): Promise<SessionRow[]> {
  const db = await useSessions();
  const { rows } = await db.sql<{
    rows: {
      id: string;
      family: string;
      created_at: number;
      updated_at: number;
      expires_at: number;
    }[];
  }>`SELECT id, family, created_at, updated_at, expires_at FROM sessions WHERE user_id = ${userId} AND expires_at > ${Date.now()} ORDER BY created_at`;
  return rows.map((row) => ({
    id: row.id,
    family: row.family,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    expiresAt: row.expires_at,
  }));
}

export async function revokeSessions(userId: string): Promise<void> {
  const db = await useSessions();
  await db.sql`DELETE FROM sessions WHERE user_id = ${userId}`;
}

function sqliteStore(): CacheDriver {
  return {
    get: readRecord as CacheDriver["get"],
    set: async (key, value) => {
      const db = await useSessions();
      if (value === null) {
        await db.sql`DELETE FROM sessions WHERE id = ${key}`;
        return;
      }
      if (!isSessionRecord(value)) throw new TypeError("not a session record");
      const { data } = value;
      await db.sql`INSERT INTO sessions (id, user_id, family, data, created_at, updated_at, expires_at) VALUES (${key}, ${data.userId}, ${data.family}, ${JSON.stringify(data)}, ${value.createdAt}, ${value.updatedAt}, ${value.expiresAt}) ON CONFLICT (id) DO UPDATE SET user_id = excluded.user_id, family = excluded.family, data = excluded.data, created_at = excluded.created_at, updated_at = excluded.updated_at, expires_at = excluded.expires_at`;
    },
  };
}

async function readRecord(key: string): Promise<OpaqueSessionRecord<SessionData> | null> {
  const db = await useSessions();
  const { rows } = await db.sql<{
    rows: { data: string; created_at: number; updated_at: number; expires_at: number }[];
  }>`SELECT data, created_at, updated_at, expires_at FROM sessions WHERE id = ${key}`;
  const row = rows[0];
  if (row === undefined) return null;
  return {
    data: JSON.parse(row.data) as SessionData,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    expiresAt: row.expires_at,
  };
}

function isSessionRecord(value: unknown): value is OpaqueSessionRecord<SessionData> {
  if (typeof value !== "object" || value === null) return false;
  const { data } = value as Partial<OpaqueSessionRecord<Partial<SessionData>>>;
  return typeof data?.userId === "string" && typeof data.family === "string";
}

let sessions: ReturnType<typeof setUp> | undefined;

function useSessions(): ReturnType<typeof setUp> {
  return (sessions ??= setUp());
}

async function setUp() {
  const db = useDatabase();
  await db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      family TEXT NOT NULL,
      data TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sessions_user_id ON sessions (user_id);
  `);
  return db;
}
