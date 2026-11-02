import { defineEventHandler } from "nuxt/server";

export default defineEventHandler(async (event) => {
  const session = await requireAuthSession(event);
  const identities = await listIdentities(session.userId);

  return { ...session, identities };
});
