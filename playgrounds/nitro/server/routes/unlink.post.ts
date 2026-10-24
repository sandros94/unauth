import { HTTPError, defineHandler } from "nitro";
import { readBody } from "nitro/h3";

import { listIdentities, unlinkIdentity } from "../utils/accounts.ts";
import { requireAuthSession } from "../utils/session.ts";

export default defineHandler(async (event) => {
  const session = await requireAuthSession(event);
  const body: { provider?: unknown; subject?: unknown } | undefined = await readBody(event);

  if (typeof body?.provider !== "string" || typeof body.subject !== "string")
    throw new HTTPError({ status: 400, message: "provider and subject required" });

  const { userId } = session.data;
  await unlinkIdentity(userId, { provider: body.provider, subject: body.subject });

  return { identities: await listIdentities(userId) };
});
