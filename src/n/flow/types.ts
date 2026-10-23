import type { JWSSignJWK } from "unjwt";
import type { CacheDriver } from "./_internal/cache/load.ts";
import type { Fetch } from "./_internal/http/shared.ts";

/** The application's registration at a provider. */
export interface OAuthClient {
  /** `client_id`. */
  id: string;
  /** `client_secret`, for `tokenAuth: "basic"` or `"body"`; a function is called for every token request. */
  secret?: string | (() => string | Promise<string>);
  /** Private JWK signing the client assertion of `tokenAuth: "private_key_jwt"` (RFC 7523). */
  privateKey?: JWSSignJWK;
}

/** A token endpoint's successful answer (RFC 6749 §5.1). */
export interface OAuthTokens {
  access_token: string;
  /** As the provider spelled it; compare case-insensitively. */
  token_type: string;
  /** Seconds; parsed when the provider sends a string. */
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
  id_token?: string;
  /** The token endpoint's response body as received. */
  raw: Record<string, unknown>;
}

/** Claims of a verified OpenID Connect id_token. */
export interface IdTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  nonce?: string;
  azp?: string;
  at_hash?: string;
  auth_time?: number;
  [claim: string]: unknown;
}

/** Who the provider says signed in. Normalized fields are filled where the provider has them. */
export interface ProvenIdentity<TProfile = Record<string, unknown>> {
  /** The provider's `id`. */
  provider: string;
  /** The account's stable identifier at that provider. */
  subject: string;
  /** What the provider returned, typed per provider. */
  profile: TProfile;
  name?: string;
  email?: string;
  /** Whether the provider vouches for `email`; absent when it does not say. */
  emailVerified?: boolean;
  avatar?: string;
}

/** What a provider's `profile()` returns; the flow adds `provider`. */
export type ProfileResult<TProfile> = Omit<ProvenIdentity<TProfile>, "provider">;

/** What a provider's `profile()` reads the account from. */
export interface ProfileContext {
  tokens: OAuthTokens;
  /** The verified id_token's claims, on OpenID Connect providers. */
  claims?: IdTokenClaims;
  /** The userinfo endpoint's answer, when the provider has one. */
  userinfo?: Record<string, unknown>;
  /**
   * The callback's query or form parameters. Untrusted, as they pass through the browser: read only
   * what the provider sends nowhere else (a display name), never identity or email.
   */
  params: Record<string, string>;
  /** For providers that need another request (an email list, an avatar URL). */
  fetch: Fetch;
}

/**
 * How the client authenticates at the token endpoint: `body` (`client_id` and `client_secret` form
 * fields), `basic` (HTTP Basic, RFC 6749 §2.3.1), `private_key_jwt` (RFC 7523) or `none` (a public
 * client sending only `client_id`).
 */
export type TokenAuthMethod = "body" | "basic" | "private_key_jwt" | "none";

/** A provider the flow engine runs itself (OAuth 2.0 or OpenID Connect), or one running its own legs. */
export type Provider<TProfile = Record<string, unknown>> =
  | OAuthProvider<TProfile>
  | CustomProvider<TProfile>;

/** An OAuth 2.0 / OpenID Connect provider: plain data plus the function mapping its account data to an identity. */
export interface OAuthProvider<TProfile = Record<string, unknown>> {
  id: string;
  kind: "oauth2" | "oidc";
  label?: string;
  client: OAuthClient;
  /** Endpoints; with `discovery`, the ones left unset come from the issuer's metadata. */
  authorization?: string;
  token?: string;
  userinfo?: string;
  issuer?: string;
  jwks?: string;
  /**
   * Read endpoints from `${issuer}/.well-known/openid-configuration`, cached for ten minutes per
   * issuer.
   */
  discovery: boolean;
  scopes: string[];
  scopeSeparator: " " | ",";
  /** The PKCE method; `false` for a provider without PKCE. */
  pkce: false | "S256" | "plain";
  /** Send and check a `nonce`; on by default for OpenID Connect. */
  nonce: boolean;
  /**
   * Whether an OpenID Connect provider needs the `openid` scope. `false` for a provider that
   * returns an id_token without it; the nonce and the id_token are checked all the same.
   *
   * @default true
   */
  openidScope?: boolean;
  /**
   * Require the RFC 9207 `iss` authorization response parameter, equal to `issuer`. Unset, it is
   * on when the discovery metadata has `authorization_response_iss_parameter_supported: true`.
   * Either way, an `iss` naming another issuer is refused.
   */
  issuerParameter?: boolean;
  /**
   * Development only: hosts whose endpoints may use plain `http:`. Exact hostnames or IP literals
   * (IPv6 in brackets), compared case-insensitively; tokens and client secrets travel to them in
   * cleartext. Loopback hosts are allowed without being listed.
   */
  insecureHosts?: string[];
  tokenAuth: TokenAuthMethod;
  responseMode: "query" | "form_post";
  authorizationParams: Record<string, string>;
  tokenParams: Record<string, string>;
  userinfoHeaders: Record<string, string>;
  profile: (context: ProfileContext) => Promise<ProfileResult<TProfile>>;
}

/**
 * A provider that runs its own two legs over the engine's flow: the engine keeps `state`, the
 * return path, the link intent and the sealed record, parses the callback and checks `state` and
 * the provider's `error`; the provider builds the URL the user is sent to and turns the callback
 * into an identity, keeping what it needs between the legs in the record's `data`.
 */
export interface CustomProvider<TProfile = Record<string, unknown>> {
  id: string;
  kind: "custom";
  label?: string;
  /** The callback URL the provider registered, used when the start options name none. */
  redirectUri?: string;
  /** How the provider sends the user back; a `form_post` callback is a `POST` to the same route. @default "query" */
  responseMode?: "query" | "form_post";
  /** The first leg: where to send the user, and what to seal in the record for `complete`. */
  start: (context: CustomStartContext) => Promise<CustomStart>;
  /** The second leg: the callback, with the record `start` sealed, into the proven identity. */
  complete: (context: CustomCompleteContext) => Promise<CustomFlowResult<TProfile>>;
}

/** What both legs of a custom provider receive. */
export interface CustomFlowContext {
  request: Request;
  /** The flow record as the engine keeps it; `data` is the provider's own. */
  record: FlowRecord;
  fetch: Fetch;
  now: () => number;
  cache?: CacheDriver;
}

/** What `CustomProvider.start` receives. */
export interface CustomStartContext extends CustomFlowContext {
  /** The callback URL, replayed by the engine as `record.redirectUri`. */
  redirectUri: string;
  /** Which account signs in (a handle, an email, a username), when the request named one. */
  login?: string;
  /** Replaces the provider's scopes. */
  scopes?: string[];
  /** Extra authorization parameters the request asked for. */
  params?: Record<string, string>;
}

/**
 * What `CustomProvider.start` returns: the started flow, with where the user is sent and what to
 * seal; or a relocation, which sends the user to start over at another URL and records no flow.
 * The engine seals the request's intent and origin host beside a relocation and returns the user
 * to that host once the sign-in completes.
 */
export type CustomStart =
  | {
      /** Where the user is sent. */
      url: URL | string;
      /** Sealed into the record as `data`, for `complete`. */
      data?: Record<string, unknown>;
      relocate?: undefined;
    }
  | {
      /**
       * Where the user starts over; no flow is recorded. The engine seals the request's intent
       * and origin host beside it, as `unauth_intent`, for the start there to read back, and
       * returns the user to the origin host once the sign-in completes: relocate only a request
       * whose host the provider vouches for.
       */
      relocate: URL | string;
    };

/** What `CustomProvider.complete` receives. */
export interface CustomCompleteContext extends CustomFlowContext {
  /** The callback's query or form parameters, `state` already checked. Untrusted beyond that. */
  params: Record<string, string>;
}

/** What `CustomProvider.complete` returns; `tokens` only when the provider hands them on. */
export interface CustomFlowResult<TProfile = Record<string, unknown>> {
  identity: ProfileResult<TProfile>;
  tokens?: OAuthTokens;
}

/** The input of `defineProvider`: an {@link OAuthProvider} whose defaulted members may be left out. */
export interface ProviderConfig<TProfile = Record<string, unknown>> extends Partial<
  Omit<OAuthProvider<TProfile>, "id" | "kind" | "client" | "pkce" | "profile">
> {
  id: string;
  kind: "oauth2" | "oidc";
  client: OAuthClient;
  /** `true` is `"S256"`. @default "S256" */
  pkce?: boolean | "S256" | "plain";
  profile: (context: ProfileContext) => ProfileResult<TProfile> | Promise<ProfileResult<TProfile>>;
}

/** The input of `defineProvider` for a {@link CustomProvider}: the provider itself. */
export type CustomProviderConfig<TProfile = Record<string, unknown>> = CustomProvider<TProfile>;

/**
 * What `startFlow` keeps for `completeFlow`, sealed as JSON: `link` must survive a JSON round
 * trip. A store or a custom provider sees `link` as `unknown`.
 */
export interface FlowRecord<TLink = unknown> {
  /** The `id` of the provider the flow was started for. */
  provider: string;
  state: string;
  /** The exact `redirect_uri` sent, replayed at the token endpoint. */
  redirectUri: string;
  /** PKCE verifier. */
  verifier?: string;
  nonce?: string;
  /** Same-origin path to return to after sign-in. */
  redirect?: string;
  /** The application's link intent, as `startFlow` was given it. */
  link?: TLink;
  /** Provider-private values; open to any provider. */
  data?: Record<string, unknown>;
  /** The host the user started on before a relocation, to return to after the sign-in. */
  returnHost?: string;
}

/** A completed sign-in: the proven identity and what the flow carried. */
export interface FlowResult<TProfile = Record<string, unknown>, TLink = never> {
  identity: ProvenIdentity<TProfile>;
  /** The provider's tokens; absent when a custom provider keeps none past the sign-in. */
  tokens?: OAuthTokens;
  /**
   * The link intent `startFlow` was given, untouched: the account in `identity` is proven, whether
   * the user who asked is still the signed-in one is the application's to check.
   */
  link?: TLink;
  /** The same-origin path given to `startFlow`. */
  redirect?: string;
}

/**
 * A server-side store of flow records; the sealed cookie then carries only the record's id. `put`
 * takes a `ttl` in seconds; `take` returns a record once and deletes it, `undefined` when absent.
 */
export interface FlowStore {
  put: (id: string, record: FlowRecord, options: { ttl: number }) => Promise<void>;
  take: (id: string) => Promise<FlowRecord | undefined>;
}
