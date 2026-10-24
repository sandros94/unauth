import { type H3Event, HTTPError } from "nitro";
import { useRuntimeConfig } from "nitro/runtime-config";
import { deriveKey } from "unauth/n";
import { defineGitHubHandler } from "unauth/n/providers/github";

import { findOrCreateUser, linkIdentity } from "../../utils/accounts.ts";
import { useAuthSession } from "../../utils/session.ts";

export default defineGitHubHandler({
  clientId: useRuntimeConfig().github.clientId,
  clientSecret: useRuntimeConfig().github.clientSecret,
  key: () => deriveKey(useRuntimeConfig().authSecret, { info: "unauth:flow" }),
  origin: useRuntimeConfig().public.origin,
  onStart: async (event: H3Event) => {
    const session = await useAuthSession(event);
    return session.id ? { memo: { userId: session.data.userId } } : undefined;
  },
  onSuccess: async (event, { identity, memo }) => {
    const session = await useAuthSession(event);
    if (memo) {
      if (session.data.userId !== memo.userId) {
        throw new HTTPError({ status: 401, message: "The session changed during the link" });
      }
      await linkIdentity(memo.userId, identity);
      return;
    }
    const user = await findOrCreateUser(identity);
    await session.clear();
    await session.update({
      userId: user.id,
      ...(identity.name ? { name: identity.name } : {}),
      signedInAt: Date.now(),
    });
  },
});
