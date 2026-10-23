import { defineEventHandler } from "nuxt/server";

export default defineEventHandler(async (event) => {
  const session = await requireAuthSession(event);

  return { id: session.id, ...session.data, expiresAt: session.expiresAt };
});
