import { createError, readBody } from "nuxt/server";

export default defineTransactionalHandler(async (event) => {
  const body: { provider?: unknown; subject?: unknown } | undefined = await readBody(event);
  if (typeof body?.provider !== "string" || typeof body.subject !== "string")
    throw createError({ statusCode: 400, message: "provider and subject required" });

  const key = await sessionKey(event);
  if (!key) throw createError({ statusCode: 401, message: "Sign in first" });
  const userId = await unlinkIdentity(event, key, {
    provider: body.provider,
    subject: body.subject,
  });
  await useAuthSession(event).rotate();

  return { identities: await listIdentities(event, userId) };
});
