import { defineEventHandler } from "nuxt/server";

export default defineEventHandler(async (event) => {
  const session = await requireAuthSession(event);
  const identities = await listIdentities(session.data.userId);

  return { id: session.id, ...session.data, identities, expiresAt: session.expiresAt };
});
