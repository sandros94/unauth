import { createError, defineEventHandler } from "nuxt/server";

export default defineEventHandler(async (event) => {
  const key = await sessionKey(event);
  const now = Date.now();
  const current = key
    ? await useDB(event).query.sessions.findFirst({
        where: {
          tokenHash: key,
          OR: [{ expiresAt: { gt: now } }, { expiresAt: { isNull: true } }],
        },
        columns: { id: true, data: true, expiresAt: true },
        with: {
          user: {
            columns: { createdAt: true },
            with: {
              identities: {
                columns: { provider: true, subject: true, name: true, email: true, linkedAt: true },
                orderBy: { linkedAt: "asc" },
              },
            },
          },
        },
      })
    : undefined;
  if (!current) throw createError({ statusCode: 401, message: "Sign in first" });

  return {
    id: current.id,
    ...current.data,
    memberSince: current.user.createdAt,
    identities: current.user.identities,
    expiresAt: current.expiresAt,
  };
});
