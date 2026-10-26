import { defineEventHandler } from "nuxt/server";

export default defineEventHandler(async (event) => {
  const session = await requireAuthSession(event);
  await deleteUser(session.data.userId);
  await session.clear();

  return { ok: true };
});
