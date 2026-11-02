import { defineEventHandler } from "nuxt/server";

export default defineEventHandler(async (event) => {
  await terminateSession(event);

  return { ok: true };
});
