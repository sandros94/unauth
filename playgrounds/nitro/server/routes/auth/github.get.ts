import { useRuntimeConfig } from "nitro/runtime-config";
import { deriveKey } from "unauth/n";
import { defineGitHubHandler } from "unauth/n/providers/github";

import { useAuthSession } from "../../utils/session.ts";

export default defineGitHubHandler({
  clientId: useRuntimeConfig().github.clientId,
  clientSecret: useRuntimeConfig().github.clientSecret,
  key: () => deriveKey(useRuntimeConfig().authSecret, { info: "unauth:flow" }),
  origin: useRuntimeConfig().public.origin,
  session: useAuthSession,
});
