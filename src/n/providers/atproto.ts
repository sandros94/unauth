import { configError } from "../flow/_internal/http/shared.ts";
import { defineProvider } from "../flow/provider.ts";
import type { CustomProvider } from "../flow/types.ts";
import type { WebRequestEvent } from "../request-event.ts";
import { type PresetHandler, type PresetHandlerConfig, presetHandler } from "./_internal/shared.ts";
import { type AtprotoProfile, complete } from "./_internal/atproto/callback.ts";
import { type AtprotoClient, devOriginsOf, resolveClient } from "./_internal/atproto/client.ts";
import { resolversOf, start } from "./_internal/atproto/flow.ts";

export type { AtprotoProfile } from "./_internal/atproto/callback.ts";
export type { AtprotoClient, AtprotoClientMetadata } from "./_internal/atproto/client.ts";
export { type DpopKey, type DpopProofOptions, createDpopProof } from "./_internal/atproto/dpop.ts";

/** Options of {@link defineAtprotoProvider}. */
export interface AtprotoProviderConfig {
  /** @default "atproto" */
  id?: string;
  /** @default "AT Protocol" */
  label?: string;
  /**
   * The URL the client metadata document is published at: `https://`, no port. An `http://` URL
   * on a loopback host or one of `devOrigins`, or no `clientId` with an `http:` loopback `redirectUri`,
   * selects the atproto development client (`http://localhost?redirect_uri=…&scope=…`), which
   * publishes no document.
   */
  clientId?: string;
  /**
   * The callback URL, listed in the client metadata; `https:` for a published client. The
   * development client's callback is on a loopback IP (`http://127.0.0.1:3000/…`,
   * `http://[::1]:3000/…`; the atproto profile refuses `localhost`, RFC 8252 §8.3); a callback on
   * one of `devOrigins` is registered on `127.0.0.1`.
   */
  redirectUri: string;
  /**
   * Development only: origins the app is also reached on with the development client, such as
   * `http://localhost:3000`. A `redirectUri` on one of them is registered on `127.0.0.1`. A sign-in
   * started on one of them is sent to the same URL on the callback's host, the flow recorded on
   * both; the sign-in handler then returns the completed result to the starting origin in a
   * sealed, single-use, one-minute token, redeemed there in the browser that started, and
   * `onSuccess` runs there. They are trusted origins of every sign-in on this provider
   * (`trustedOrigins`).
   *
   * @default []
   */
  devOrigins?: string[];
  /** Must include `atproto`. @default ["atproto"] */
  scopes?: string[];
  /** Shown to the user on the authorization server's consent screen. */
  clientName?: string;
  clientUri?: string;
  logoUri?: string;
  tosUri?: string;
  policyUri?: string;
  /**
   * Development only: lets the PDS, authorization server and endpoints named by DID documents and
   * server metadata use plain `http:`, for a PDS run locally. Off, those must be `https:`: with
   * it on, any account's documents can point this server at plain-http services it can reach.
   *
   * @default false
   */
  allowHttp?: boolean;
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
 * AT Protocol (Bluesky and every other PDS) as a public client, sign-in only: `loginHint` names the
 * account (a handle or a DID) or the server to start from (an `https://` URL); the account's
 * authorization server is discovered through its DID document and PDS; the request is pushed
 * (PAR) with PKCE and a DPoP proof signed by a key minted for this sign-in; the callback's `iss`,
 * the token's `sub` and the account's PDS are checked against each other. The DPoP-bound tokens
 * are not kept: the result is who signed in. Throws `ERR_UNAUTH_CONFIG_INVALID` for a config that
 * cannot work (see `clientId`, `redirectUri`, `scopes`).
 */
export function defineAtprotoProvider(config: AtprotoProviderConfig): AtprotoProvider {
  const devOrigins = devOriginsOf(config.devOrigins);
  const client = resolveClient(config, devOrigins);
  const scopes = config.scopes ?? ["atproto"];
  if (!scopes.includes("atproto")) {
    throw configError(`The AT Protocol provider needs the "atproto" scope.`);
  }
  const resolvers = resolversOf(config);

  const provider = defineProvider<AtprotoProfile>({
    id: config.id ?? "atproto",
    kind: "custom",
    label: config.label ?? "AT Protocol",
    trustedOrigins: devOrigins,
    start: (context) => start(context, { client, scopes, resolvers, devOrigins }),
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
  TResult = never,
  TEvent extends WebRequestEvent = WebRequestEvent,
  TMemo = never,
> = PresetHandlerConfig<AtprotoProviderPart, AtprotoProfile, TResult, TEvent, TMemo>;

/**
 * Both legs of an AT Protocol sign-in on one route: `defineSignInHandler` on the provider, the options
 * split between them by the provider's keys. `redirectUri` is both the provider's callback and the
 * sign-in's. The account (a handle, a DID or a server) is `onStart`'s `loginHint`: the handler
 * reads nothing from the request, the application does, from the form it serves. Naming the
 * account picks the server the flow's `state` is pushed to, so the start is taken only as a `POST`
 * from the application's own origin (`ERR_AUTHN_CROSS_SITE_START` otherwise).
 */
export const defineAtprotoHandler: PresetHandler<AtprotoProviderPart, AtprotoProfile> =
  /* @__PURE__ */ presetHandler(atprotoProviderOf, {
    keys: [
      "provider",
      "id",
      "label",
      "clientId",
      "redirectUri",
      "devOrigins",
      "scopes",
      "clientName",
      "clientUri",
      "logoUri",
      "tosUri",
      "policyUri",
      "dnsResolver",
      "plcDirectory",
      "allowHttp",
    ],
    shared: ["redirectUri"],
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
