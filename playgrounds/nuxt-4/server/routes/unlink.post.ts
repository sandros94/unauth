import { createError, defineEventHandler, readBody } from "nuxt/server";

export default defineEventHandler(async (event) => {
  const session = await requireAuthSession(event);
  const body: { provider?: unknown; subject?: unknown } | undefined = await readBody(event);

  if (typeof body?.provider !== "string" || typeof body.subject !== "string")
    throw createError({ statusCode: 400, message: "provider and subject required" });

  const { userId } = session.data;
  await unlinkIdentity(userId, { provider: body.provider, subject: body.subject });

  return { identities: await listIdentities(userId) };
});
