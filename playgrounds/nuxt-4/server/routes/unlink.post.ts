import { createError, defineEventHandler, readBody } from "nuxt/server";

export default defineEventHandler(async (event) => {
  const session = await requireAuthSession(event);
  const body: { provider?: unknown; subject?: unknown } | undefined = await readBody(event);

  if (typeof body?.provider !== "string" || typeof body.subject !== "string")
    throw createError({ statusCode: 400, message: "provider and subject required" });

  const { userId, signedInAt } = session.data;
  await unlinkIdentity(userId, { provider: body.provider, subject: body.subject });
  const identities = await listIdentities(userId);
  const current =
    identities.find(
      (entry) => entry.provider === session.data.provider && entry.subject === session.data.subject,
    ) ?? identities[0]!;

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
