import { configError } from "../flow/_http.ts";
import { defineProvider } from "../flow/provider.ts";
import type { CustomProvider } from "../flow/types.ts";
import type { AuthSessionData } from "../_session-data.ts";
import type { HandlerEvent } from "../handler.ts";
import { type PresetHandler, type PresetHandlerConfig, presetHandler } from "./_shared.ts";
import { type AtprotoProfile, complete } from "./_atproto/callback.ts";
import { type AtprotoClient, resolveClient } from "./_atproto/client.ts";
import { resolversOf, start } from "./_atproto/flow.ts";

export type { AtprotoProfile } from "./_atproto/callback.ts";
export type { AtprotoClient, AtprotoClientMetadata } from "./_atproto/client.ts";
export { type DpopKey, type DpopProofOptions, createDpopProof } from "./_atproto/dpop.ts";

/** Options of {@link defineAtprotoProvider}. */
export interface AtprotoProviderConfig {
  /** @default "atproto" */
  id?: string;
  /** @default "AT Protocol" */
  label?: string;
  /**
   * The URL the client metadata document is published at, which is the app's identity to every
   * authorization server: `https://`, no port. An `http://` URL on a loopback host, which no
   * server could fetch, selects the spec's development client instead
   * (`http://localhost?redirect_uri=…&scope=…`), as does leaving it unset with a loopback
   * `redirectUri`; the development client publishes no document.
   */
  clientId?: string;
  /**
   * The callback URL, listed in the client metadata. With the development client it must be on a
   * loopback IP (`http://127.0.0.1:3000/…`, `http://[::1]:3000/…`): the atproto profile refuses
   * `localhost` there (RFC 8252 §8.3), so a `localhost` callback is only accepted through
   * `devHosts`, which maps it to `127.0.0.1`.
   */
  redirectUri: string;
  /**
   * Development only: hosts the app is also reached on, such as `localhost`, when the development
   * client's callback must be the loopback IP. A `redirectUri` on one of them is registered on
   * `127.0.0.1` instead, and a sign-in started on one of them is first sent to the same URL on
   * that IP, before any cookie is set, so the flow cookie comes back with the callback; the
   * session then lives on that host. Off by default.
   */
  devHosts?: string[];
  /** Must include `atproto`. @default ["atproto"] */
  scopes?: string[];
  /** Shown to the user on the authorization server's consent screen. */
  clientName?: string;
  clientUri?: string;
  logoUri?: string;
  tosUri?: string;
  policyUri?: string;
  /** A DNS-over-HTTPS resolver answering `application/dns-json`. @default "https://cloudflare-dns.com/dns-query" */
  dnsResolver?: string;
  /** The `did:plc` directory. @default "https://plc.directory" */
  plcDirectory?: string;
}

/** An AT Protocol provider: a custom provider that also knows its client. */
export interface AtprotoProvider extends CustomProvider<AtprotoProfile> {
  client: AtprotoClient;
  /** The callback as registered; the engine uses it when the sign-in handler names none. */
  redirectUri: string;
  scopes: string[];
}

/**
 * AT Protocol (Bluesky and every other PDS) as a public client, sign-in only: `login` names the
 * account (a handle or a DID) or the server to start from (an `https://` URL); the account's
 * authorization server is discovered through its DID document and PDS; the request is pushed
 * (PAR) with PKCE and a DPoP proof signed by a key minted for this sign-in; the callback's `iss`,
 * the token's `sub` and the account's PDS are checked against each other. The DPoP-bound tokens
 * are not kept: who signed in is the result.
 */
export function defineAtprotoProvider(config: AtprotoProviderConfig): AtprotoProvider {
  const devHosts = config.devHosts ?? [];
  const client = resolveClient(config, devHosts);
  const scopes = config.scopes ?? ["atproto"];
  if (!scopes.includes("atproto")) {
    throw configError(`The AT Protocol provider needs the "atproto" scope.`);
  }
  const resolvers = resolversOf(config);

  const provider = defineProvider<AtprotoProfile>({
    id: config.id ?? "atproto",
    kind: "custom",
    label: config.label ?? "AT Protocol",
    start: (context) => start(context, { client, scopes, resolvers, devHosts }),
    complete: (context) => complete(context, { client, resolvers }),
  });
  return { ...provider, redirectUri: client.redirectUri, client, scopes };
}

/**
 * The provider part of {@link defineAtprotoHandler}'s options: an inline config, or a provider
 * defined once elsewhere (to serve its `client.metadata` from another route too).
 */
export type AtprotoProviderPart =
  | (AtprotoProviderConfig & { provider?: never })
  | ({ provider: AtprotoProvider; redirectUri?: string } & {
      [K in Exclude<keyof AtprotoProviderConfig, "redirectUri">]?: never;
    });

/** Options of {@link defineAtprotoHandler}: the provider part and `defineSignInHandler`'s, in one object. */
export type AtprotoHandlerConfig<
  TSession extends object = AuthSessionData,
  TResult = never,
  TEvent extends HandlerEvent = HandlerEvent,
> = PresetHandlerConfig<AtprotoProviderPart, AtprotoProfile, TSession, TResult, TEvent>;

/**
 * Both legs of an AT Protocol sign-in on one route: `defineSignInHandler` on the provider, the options
 * split between them by the provider's keys. `redirectUri` is both the provider's callback and the
 * sign-in's. The account comes from the request's `?login=` (a handle, a DID or a server) unless
 * `onStart` names one.
 */
export const defineAtprotoHandler: PresetHandler<AtprotoProviderPart, AtprotoProfile> =
  /* @__PURE__ */ presetHandler(atprotoProviderOf, {
    keys: [
      "provider",
      "id",
      "label",
      "clientId",
      "redirectUri",
      "devHosts",
      "scopes",
      "clientName",
      "clientUri",
      "logoUri",
      "tosUri",
      "policyUri",
      "dnsResolver",
      "plcDirectory",
    ],
    shared: ["redirectUri"],
    login: (event) => new URL(event.req.url).searchParams.get("login") ?? undefined,
  });

function atprotoProviderOf(part: AtprotoProviderPart): AtprotoProvider {
  if (part.provider === undefined) return defineAtprotoProvider(part);
  const clash = Object.entries(part)
    .filter(([name, value]) => value !== undefined && name !== "provider" && name !== "redirectUri")
    .map(([name]) => `"${name}"`);
  if (clash.length > 0) {
    throw configError(
      `The AT Protocol sign-in takes a "provider" or the provider's options, not both: ${clash.join(", ")} belong on the provider.`,
    );
  }
  return part.provider;
}
