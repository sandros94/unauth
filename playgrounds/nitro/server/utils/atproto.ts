import { useRuntimeConfig } from "nitro/runtime-config";
import { defineAtprotoProvider } from "unauth/n/providers/atproto";

// The app's identity is its client metadata document. In development that URL is on localhost,
// which no server can fetch, so the provider uses the spec's development client instead; its
// callback must be a loopback IP, which `devHosts` maps `localhost` to, moving a start on
// localhost there first.
export const atproto = defineAtprotoProvider({
  redirectUri: `${useRuntimeConfig().public.origin}/auth/atproto`,
  devHosts: import.meta.dev ? ["localhost"] : undefined,
  clientId: `${useRuntimeConfig().public.origin}/oauth-client-metadata.json`,
  clientName: "unauth playground",
  clientUri: useRuntimeConfig().public.origin,
});
