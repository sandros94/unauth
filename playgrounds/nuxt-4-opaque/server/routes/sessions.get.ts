import { defineEventHandler } from "nuxt/server";

export default defineEventHandler(async (event) => {
  const session = await requireAuthSession(event);

  return { current: session.id, sessions: await listSessions(session.data.userId) };
});
