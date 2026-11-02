import { defineHandler } from "nitro";

import { deleteUser } from "../utils/accounts.ts";
import { requireAuthSession } from "../utils/session.ts";

export default defineHandler(async (event) => {
  const session = await requireAuthSession(event);
  await deleteUser(session.data.userId);
  await session.clear();

  return { ok: true };
});
