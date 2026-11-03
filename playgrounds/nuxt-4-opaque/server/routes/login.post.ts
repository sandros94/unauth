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

  const user = await verifyPassword(event, body.user, body.password);
  if (user === undefined) throw createError({ statusCode: 401, message: "Wrong user or password" });

  const session = useAuthSession(event);
  await session.clear();
  const record = await session.update({ userId: user.id, signedInAt: Date.now() });

  return { id: record?.id, userId: record?.data.userId, expiresAt: record?.expiresAt };
});
