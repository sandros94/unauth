import { defineEventHandler } from "nuxt/server";

export default defineEventHandler(async (event) => {
  const { userId } = await requireAuthSession(event);
  await revokeSessions(userId);
  await deleteUser(userId);
  await terminateSession(event);

  return { ok: true };
});
