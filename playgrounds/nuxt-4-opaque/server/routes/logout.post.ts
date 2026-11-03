import { defineEventHandler } from "nuxt/server";

export default defineEventHandler(async (event) => {
  await useAuthSession(event).clear();

  return { ok: true };
});
