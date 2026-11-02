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

  const user = await verifyPassword(body.user, body.password);
  if (user === undefined) throw createError({ statusCode: 401, message: "Wrong user or password" });

  return createSession(event, { userId: user.id });
});
