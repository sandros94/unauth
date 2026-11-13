import type { DatabaseSync } from "node:sqlite";
import type { OpaqueSessionRecord, OpaqueSessionStore } from "unauth/session";
import { hashOpaqueToken } from "unauth/token";
import { type Row, integer, text } from "./rows.ts";

export interface SessionData {
  subject: string;
  grants?: unknown;
}

export function sqliteSessionStore(db: DatabaseSync): OpaqueSessionStore<SessionData> {
  return {
    find: async (token) => {
      const row = db
        .prepare(
          `SELECT id, data, created_at, updated_at, expires_at FROM sessions
           WHERE token_hash = ?`,
        )
        .get(await hashOpaqueToken(token));
      return row === undefined ? null : recordOf(row);
    },
    save: async (token, record) => {
      db.prepare(
        `INSERT INTO sessions (token_hash, id, subject, data, created_at, updated_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (token_hash) DO UPDATE SET id = excluded.id, subject = excluded.subject,
           data = excluded.data, updated_at = excluded.updated_at, expires_at = excluded.expires_at`,
      ).run(
        await hashOpaqueToken(token),
        record.id,
        record.data.subject,
        JSON.stringify(record.data),
        record.createdAt,
        record.updatedAt,
        record.expiresAt ?? null,
      );
    },
    touch: async (token, times) => {
      const { changes } = db
        .prepare("UPDATE sessions SET updated_at = ?, expires_at = ? WHERE token_hash = ?")
        .run(times.updatedAt, times.expiresAt ?? null, await hashOpaqueToken(token));
      return changes > 0;
    },
    rekey: async (from, to, times) => {
      const { changes } = db
        .prepare(
          "UPDATE sessions SET token_hash = ?, updated_at = ?, expires_at = ? WHERE token_hash = ?",
        )
        .run(
          await hashOpaqueToken(to),
          times.updatedAt,
          times.expiresAt ?? null,
          await hashOpaqueToken(from),
        );
      return changes > 0;
    },
    delete: async (token) => {
      db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(await hashOpaqueToken(token));
    },
  };
}

function recordOf(row: Row): OpaqueSessionRecord<SessionData> | null {
  const data: unknown = JSON.parse(text(row, "data"));
  if (typeof data !== "object" || data === null || !("subject" in data)) return null;
  const { subject } = data;
  if (typeof subject !== "string") return null;
  return {
    id: text(row, "id"),
    createdAt: integer(row, "created_at") ?? 0,
    updatedAt: integer(row, "updated_at") ?? 0,
    expiresAt: integer(row, "expires_at"),
    data: "grants" in data ? { subject, grants: data.grants } : { subject },
  };
}
