import { createError, defineEventHandler, readBody } from "nuxt/server";

export default defineEventHandler(async (event) => {
  const body: { user?: unknown; password?: unknown } | undefined = await readBody(event);

  if (
    typeof body?.user !== "string" ||
    body.user === "" ||
    typeof body.password !== "string" ||
    body.password === ""
  )
    throw createError({ statusCode: 400, message: "user and password required" });

  const user = await registerPassword(body.user, body.password);

  const session = await useAuthSession(event);
  await session.clear();
  await session.update({
    userId: user.id,
    provider: "password",
    subject: body.user,
    signedInAt: Date.now(),
  });

  return { id: session.id, subject: session.data.subject, expiresAt: session.expiresAt };
});
