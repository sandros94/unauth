import { defineHandler } from "nitro";

import { useAuthSession } from "../utils/session.ts";

export default defineHandler(async (event) => {
  const session = await useAuthSession(event);
  await session.clear();

  return { ok: true };
});
