import { HTTPError, defineHandler } from "nitro";
import { readBody } from "nitro/h3";

import { listIdentities, unlinkIdentity } from "../utils/accounts.ts";
import { requireAuthSession } from "../utils/session.ts";

export default defineHandler(async (event) => {
  const session = await requireAuthSession(event);
  const body: { provider?: unknown; subject?: unknown } | undefined = await readBody(event);

  if (typeof body?.provider !== "string" || typeof body.subject !== "string")
    throw new HTTPError({ status: 400, message: "provider and subject required" });

  const { userId, signedInAt } = session.data;
  await unlinkIdentity(userId, { provider: body.provider, subject: body.subject });
  const identities = await listIdentities(userId);
  const current =
    identities.find(
      (entry) => entry.provider === session.data.provider && entry.subject === session.data.subject,
    ) ?? identities[0];

  await session.clear();
  await session.update({
    userId,
    provider: current.provider,
    subject: current.subject,
    ...(current.name === undefined ? {} : { name: current.name }),
    signedInAt,
  });

  return { identities };
});
