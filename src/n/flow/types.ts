import type { JWSSignJWK } from "unjwt";
import type { CacheDriver } from "./_cache.ts";
import type { Fetch } from "./_http.ts";

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
  /** The token endpoint's response as received, before unauth read the standard fields. */
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
  /** The provider's tokens; absent when a custom provider keeps none past the sign-in. */
  tokens?: OAuthTokens;
}

/** What a provider's `profile()` returns; the flow adds `provider` and `tokens`. */
export type ProfileResult<TProfile> = Omit<ProvenIdentity<TProfile>, "provider" | "tokens">;

/** What a provider's `profile()` reads the account from. */
export interface ProfileContext {
  tokens: OAuthTokens;
  /** The verified id_token's claims, on OpenID Connect providers. */
  claims?: IdTokenClaims;
  /** The userinfo endpoint's answer, when the provider has one. */
  userinfo?: Record<string, unknown>;
  /**
   * The callback's query or form parameters. Untrusted: they passed through the browser, so read
   * only what a provider sends nowhere else (a display name), never identity or email.
   */
  params: Record<string, string>;
  /** For providers that need another request (an email list, an avatar URL). */
  fetch: Fetch;
}

/** How the client authenticates at the token endpoint. Closed. */
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
  /** `false` only for providers that cannot do PKCE. */
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
   * Development only: hosts whose endpoints may use plain `http:`, for a provider on a private
   * network. Exact hostnames or IP literals (IPv6 in brackets), compared case-insensitively. Tokens
   * and client secrets travel in cleartext on that network, so in anything shared prefer `https:`
   * with a local CA (mkcert). Loopback hosts are allowed without being listed.
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
 * What `CustomProvider.start` returns: the flow started, with where the user is sent and what to
 * seal; or a relocation, where the user is sent to start over elsewhere and nothing is sealed (a
 * sign-in that must start on another host, so its cookie comes back).
 */
export type CustomStart =
  | {
      /** Where the user is sent. */
      url: URL | string;
      /** Sealed into the record as `data`, for `complete`. */
      data?: Record<string, unknown>;
      /**
       * The host the user started on before a relocation, to be sent back to once the sign-in
       * completed: the handler hands the result over in a sealed token. Only a host the provider
       * vouches for (a `devHosts` entry), never one read from the request as is.
       */
      returnHost?: string;
      relocate?: undefined;
    }
  | {
      /** Where the user starts over; no flow is recorded. */
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

/** What `startFlow` remembers for `completeFlow`. */
export interface FlowRecord {
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
  /** The signed-in user who asked to link this provider. */
  link?: { userId: string };
  /** Provider-private values; open to any provider. */
  data?: Record<string, unknown>;
  /** The host the user started on before a relocation, to return to after the sign-in. */
  returnHost?: string;
}

/**
 * The driver keeping flow records server-side (a KV, a cache) instead of in the sealed cookie,
 * which then only carries the record's id. `take` must return a record once and delete it.
 */
export interface FlowStore {
  put: (id: string, record: FlowRecord, options: { ttl: number }) => Promise<void>;
  take: (id: string) => Promise<FlowRecord | undefined>;
}
