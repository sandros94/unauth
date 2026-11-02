import { useRuntimeConfig } from "nitro/runtime-config";
import { defineAtprotoProvider } from "unauth/n/providers/atproto";

export const atproto = defineAtprotoProvider({
  redirectUri: `${useRuntimeConfig().public.origin}/auth/atproto`,
  devOrigins: import.meta.dev ? [useRuntimeConfig().public.origin] : undefined,
  clientId: `${useRuntimeConfig().public.origin}/oauth-client-metadata.json`,
  clientName: "unauth playground",
  clientUri: useRuntimeConfig().public.origin,
});
