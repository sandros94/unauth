import { defineHandler } from "nitro";

import { requireAuthSession } from "../utils/session.ts";

export default defineHandler(async (event) => {
  const session = await requireAuthSession(event);

  return { id: session.id, ...session.data, expiresAt: session.expiresAt };
});
