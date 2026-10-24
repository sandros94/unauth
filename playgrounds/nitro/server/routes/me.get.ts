import { defineHandler } from "nitro";

import { listIdentities } from "../utils/accounts.ts";
import { requireAuthSession } from "../utils/session.ts";

export default defineHandler(async (event) => {
  const session = await requireAuthSession(event);
  const identities = await listIdentities(session.data.userId);

  return { id: session.id, ...session.data, identities, expiresAt: session.expiresAt };
});
