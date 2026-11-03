import { createError, defineEventHandler } from "nuxt/server";

export default defineEventHandler(async (event) => {
  const key = await sessionKey(event);
  if (!key) throw createError({ statusCode: 401, message: "Sign in first" });
  const now = Date.now();
  const live = { OR: [{ expiresAt: { gt: now } }, { expiresAt: { isNull: true as const } }] };
  const rows = await useDB(event).query.sessions.findMany({
    where: { ...live, user: { sessions: { tokenHash: key, ...live } } },
    columns: { tokenHash: true, id: true, createdAt: true, updatedAt: true, expiresAt: true },
    orderBy: { createdAt: "asc" },
  });
  const current = rows.find((row) => row.tokenHash === key);
  if (!current) throw createError({ statusCode: 401, message: "Sign in first" });

  return {
    current: current.id,
    sessions: rows.map(({ tokenHash: _hash, ...row }) => row),
  };
});
