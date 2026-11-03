import { type RequestEvent, createError } from "nuxt/server";
import { and, eq, gt, isNull, or } from "drizzle-orm";
import { type OpaqueSession, type OpaqueSessionStore, defineOpaqueSession } from "unauth/session";
import { hashOpaqueToken } from "unauth/token";
import { sessions } from "../db/schema";

const definition = defineOpaqueSession<SessionData, RequestEvent>({
  store: drizzleSessionStore,
  maxAge: "30D",
  idle: "7D",
});

export function useAuthSession(event: RequestEvent): OpaqueSession<SessionData> {
  return definition.use(event);
}

export async function requireAuthSession(event: RequestEvent): Promise<SessionData> {
  const { data } = await useAuthSession(event).record;
  if (!data) throw createError({ statusCode: 401, message: "Sign in first" });
  return data;
}

export async function sessionKey(event: RequestEvent): Promise<string | undefined> {
  const { token } = useAuthSession(event);
  return token === undefined ? undefined : hashOpaqueToken(token);
}

export async function revokeSessions(event: RequestEvent, userId: string): Promise<void> {
  await useDB(event).delete(sessions).where(eq(sessions.userId, userId));
}

export function drizzleSessionStore(event?: RequestEvent): OpaqueSessionStore<SessionData> {
  const handle = useDB(event);
  const live = (tokenHash: string) =>
    and(
      eq(sessions.tokenHash, tokenHash),
      or(isNull(sessions.expiresAt), gt(sessions.expiresAt, Date.now())),
    );
  return {
    find: async (token) => {
      const row = await handle.query.sessions.findFirst({
        where: { tokenHash: await hashOpaqueToken(token) },
        columns: { id: true, createdAt: true, updatedAt: true, expiresAt: true, data: true },
      });
      return row ? { ...row, expiresAt: row.expiresAt ?? undefined } : null;
    },
    save: async (token, record) => {
      const row = {
        id: record.id,
        userId: record.data.userId,
        data: record.data,
        createdAt: record.createdAt,
        updatedAt: record.updatedAt,
        expiresAt: record.expiresAt ?? null,
      };
      await handle
        .insert(sessions)
        .values({ tokenHash: await hashOpaqueToken(token), ...row })
        .onConflictDoUpdate({ target: sessions.tokenHash, set: row });
    },
    touch: async (token, times) => {
      const moved = await handle
        .update(sessions)
        .set({ updatedAt: times.updatedAt, expiresAt: times.expiresAt ?? null })
        .where(live(await hashOpaqueToken(token)))
        .returning({ id: sessions.id });
      return moved.length > 0;
    },
    rekey: async (from, to, times) => {
      const moved = await handle
        .update(sessions)
        .set({
          tokenHash: await hashOpaqueToken(to),
          updatedAt: times.updatedAt,
          expiresAt: times.expiresAt ?? null,
        })
        .where(live(await hashOpaqueToken(from)))
        .returning({ id: sessions.id });
      return moved.length > 0;
    },
    delete: async (token) => {
      await handle.delete(sessions).where(eq(sessions.tokenHash, await hashOpaqueToken(token)));
    },
  };
}
