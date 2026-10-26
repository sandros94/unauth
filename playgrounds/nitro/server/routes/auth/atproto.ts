import { type H3Event, HTTPError } from "nitro";
import { useRuntimeConfig } from "nitro/runtime-config";
import { deriveKey } from "unauth/n";
import { defineAtprotoHandler } from "unauth/n/providers/atproto";

import { findOrCreateUser, linkIdentity } from "../../utils/accounts.ts";
import { atproto } from "../../utils/atproto.ts";
import { useAuthSession } from "../../utils/session.ts";

export default defineAtprotoHandler({
  provider: atproto,
  key: () => deriveKey(useRuntimeConfig().authSecret, { info: "unauth:flow" }),
  onStart: async (event: H3Event) => {
    const session = await useAuthSession(event);

    const loginHint =
      event.req.method === "POST" ? (await event.req.formData()).get("login") : null;

    return {
      ...(typeof loginHint === "string" && loginHint ? { loginHint } : {}),
      ...(session.id ? { memo: { userId: session.data.userId } } : {}),
    };
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
