import { defineHandler } from "nitro";

import { auth, requireAppSession } from "../utils/session.ts";
import { defineSessionGuard } from "unauth/n";

export default defineHandler({
  middleware: [defineSessionGuard(auth)],
  async handler(event) {
    const session = await requireAppSession(event);

    return { id: session.id, ...session.data, expiresAt: session.expiresAt };
  },
});
