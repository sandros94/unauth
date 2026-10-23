import { defineEventHandler, readBody, createError } from "nuxt/server";

export default defineEventHandler(async (event) => {
  const body: { user?: unknown } | undefined = await readBody(event);

  if (typeof body?.user !== "string")
    throw createError({ statusCode: 400, message: "user required" });

  // Replace, then write: nothing of whoever was signed in before carries over.
  const session = await useAuthSession(event);
  await session.clear();
  await session.update({ provider: "password", subject: body.user, signedInAt: Date.now() });

  return { id: session.id, subject: session.data.subject, expiresAt: session.expiresAt };
});
