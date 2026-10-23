import { useRuntimeConfig } from "nitro/runtime-config";
import { deriveKey } from "unauth/n";
import { defineAtprotoHandler } from "unauth/n/providers/atproto";

import { atproto } from "../../utils/atproto.ts";
import { useAuthSession } from "../../utils/session.ts";

export default defineAtprotoHandler({
  provider: atproto,
  key: () => deriveKey(useRuntimeConfig().authSecret, { info: "unauth:flow" }),
  session: useAuthSession,
});
