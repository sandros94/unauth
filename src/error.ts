/**
 * The error codes unauth defines: `ERR_AUTHN_*` for authentication (`unauth/n`), `ERR_AUTHZ_*` for
 * authorization (`unauth/z`), `ERR_SESSION_*` for opaque sessions (`unauth/session`),
 * `ERR_UNAUTH_*` for misconfiguration. {@link isUnauthError} takes this type, so a misspelled code does not compile.
 */
export type KnownUnauthErrorCode =
  | "ERR_UNAUTH_CONFIG_INVALID" // a configuration that cannot work
  // session (`unauth/session`)
  | "ERR_SESSION_TOKEN_INVALID" // the request's session token names no live session, or its session header holds no token
  | "ERR_SESSION_READONLY_EVENT" // the session cannot change: the event has no response, or it was already sent
  | "ERR_SESSION_NONE" // the request has no session to rotate
  // authn (`unauth/n`)
  | "ERR_AUTHN_UNAUTHENTICATED" // no signed-in session; for the application's own guards, never thrown by unauth
  | "ERR_AUTHN_LOGIN_HINT_REQUIRED" // the provider needs to know which account signs in (`loginHint`)
  | "ERR_AUTHN_LOGIN_HINT_INVALID" // `loginHint` names no usable account at the provider
  | "ERR_AUTHN_FLOW_EXPIRED" // no sign-in flow to complete: never started, expired or already used
  | "ERR_AUTHN_STATE_MISMATCH" // the callback does not belong to the flow this browser started
  | "ERR_AUTHN_CALLBACK_INVALID" // the callback request is not one the provider sends (a form body over the cap)
  | "ERR_AUTHN_CROSS_SITE_START" // a start that links an account or names the account was not a form submission from the application's own pages
  | "ERR_AUTHN_ORIGIN_UNTRUSTED" // a start reached the sign-in on an origin it does not run on: `redirectUri` is never derived from an untrusted Host
  | "ERR_AUTHN_PROVIDER_REFUSED" // the provider answered the authorization request with an error
  | "ERR_AUTHN_TOKEN_EXCHANGE" // the token endpoint refused or failed a code or refresh grant
  | "ERR_AUTHN_ID_TOKEN_INVALID" // an id_token failed verification
  | "ERR_AUTHN_PROFILE_INVALID" // the provider's account data does not name a usable identity
  | "ERR_AUTHN_PROVIDER_ERROR" // a provider endpoint failed or answered unusably
  | "ERR_AUTHN_TOKEN_INVALID" // a one-time token is malformed, forged or expired
  | "ERR_AUTHN_TOKEN_PURPOSE" // a one-time token was issued for another purpose
  | "ERR_AUTHN_TOKEN_USED" // a one-time token was already used
  // authz (`unauth/z`)
  | "ERR_AUTHZ_CATALOG_INVALID" // a catalog that breaks a rule of the model
  | "ERR_AUTHZ_PERMISSION_UNKNOWN" // a permission the catalog does not declare
  | "ERR_AUTHZ_PLACE_OUTSIDE" // a place the structure the catalog declares does not hold
  | "ERR_AUTHZ_MALFORMED" // a place, a permission, a role entry, a time or grants not in their one form
  | "ERR_AUTHZ_QUESTION_INVALID" // a question naming no permission, or a wildcard
  | "ERR_AUTHZ_ROLE_INVALID" // a role that is unknown where it is read, or defined against the rules on roles
  | "ERR_AUTHZ_CHANGE_REFUSED" // the author may not make this change
  | "ERR_AUTHZ_GRANTS_FORMAT" // grants of another format revision
  | "ERR_AUTHZ_GRANTS_CATALOG" // grants issued for another catalog
  | "ERR_AUTHZ_GRANTS_EARLY"; // grants read at a time before their issue

/** An {@link UnauthError} `code`: a {@link KnownUnauthErrorCode}, or any code of the application's own. */
export type UnauthErrorCode = KnownUnauthErrorCode | (string & {});

/**
 * The structured `cause` of the codes that carry one. Codes absent here have an `unknown` cause,
 * usually the error underneath.
 */
export interface UnauthErrorCauseMap {
  /**
   * Why the request's token names no session: `unknown`, no record under it (never issued, revoked,
   * or not a token at all); `expired`, its record ended and is dropped; `header`, the session
   * header named is present but holds neither a bare token nor `Bearer <token>`.
   */
  ERR_SESSION_TOKEN_INVALID:
    | { reason: "unknown" | "expired" }
    | { reason: "header"; header: string };
  /**
   * Why the callback carries no flow: `missing`, no flow cookie came back at all (the sign-in
   * started on another host, or cookies are off); `unreadable`, the cookie expired or does not
   * open; `consumed`, the flow store has no record.
   */
  ERR_AUTHN_FLOW_EXPIRED: { reason: "missing" | "unreadable" | "consumed" };
  /**
   * Why a start that links an account or names the account was refused: `method`, not a `POST`;
   * `origin`, no `Origin` header or one that is neither the request's origin nor a trusted one;
   * `cross-site`, a `Sec-Fetch-Site` other than `same-origin` on a request claiming the
   * application's own origin.
   */
  ERR_AUTHN_CROSS_SITE_START: { reason: "method" | "origin" | "cross-site" };
  /** The origin of the start that reached the sign-in on an origin it does not run on. */
  ERR_AUTHN_ORIGIN_UNTRUSTED: { origin: string };
  /** Why the callback request was refused unread: `too-large`, a `form_post` body over the cap. */
  ERR_AUTHN_CALLBACK_INVALID: { reason: "too-large" };
  /**
   * The error the provider answered the authorization request with: at the redirect URI (RFC 6749
   * §4.1.2.1) or at the pushed authorization request endpoint (RFC 9126 §2.3).
   */
  ERR_AUTHN_PROVIDER_REFUSED: OAuthErrorResponse;
  /**
   * Which check an id_token failed: `claim`, the claim at fault, with `reason: "subject"` when `sub`
   * names another account than the one expected; `reason: "missing"`, a sign-in at an OpenID
   * Connect provider returned none; neither, the signature, `iss`, `aud` or `exp` failed, with the
   * error underneath in `cause`.
   */
  ERR_AUTHN_ID_TOKEN_INVALID: {
    claim?: "sub" | "iat" | "azp" | "nonce" | "at_hash";
    reason?: "missing" | "subject";
    cause?: unknown;
  };
  /** The token endpoint's error (RFC 6749 §5.2), its HTTP status, or the detail of an unusable answer. */
  ERR_AUTHN_TOKEN_EXCHANGE: Partial<OAuthErrorResponse> & {
    status?: number;
    /** The token type the endpoint issued, when it was not the expected one. */
    token_type?: string;
    /** The scopes the endpoint granted, when they lack a required one. */
    scope?: string;
    cause?: unknown;
  };
  /**
   * Why a provider endpoint gave no usable answer: `unreachable`, no connection; `timeout`, nothing
   * within the deadline; `too-large`, a body over the cap; `status`, a failed HTTP status;
   * `malformed`, an answer that is not what its protocol says; `refused`, a server the sign-in's
   * policy does not reach; `failed`, a custom provider's own leg threw something that is not an
   * `UnauthError`. `status` is the HTTP status once one arrived, `cause` the failure underneath
   * when there is one.
   */
  ERR_AUTHN_PROVIDER_ERROR: {
    reason: "unreachable" | "timeout" | "too-large" | "status" | "malformed" | "refused" | "failed";
    status?: number;
    cause?: unknown;
  };
  /**
   * Which rule a catalog breaks, and where: `at` is the member, then the name inside it.
   * `fingerprint` is a catalog object handed in with a fingerprint that is not its own.
   */
  ERR_AUTHZ_CATALOG_INVALID: {
    reason:
      | "shape"
      | "token"
      | "duplicate"
      | "implication"
      | "cycle"
      | "manager"
      | "assigner"
      | "preset"
      | "places"
      | "fingerprint";
    at: string;
    value?: unknown;
  };
  /** What is not written in its one form, and the value found. */
  ERR_AUTHZ_MALFORMED: {
    what:
      | "place"
      | "level"
      | "value"
      | "permission"
      | "pattern"
      | "entry"
      | "role"
      | "time"
      | "roles"
      | "statement"
      | "question"
      | "grants";
    value: unknown;
  };
  /**
   * Why a role is refused: `unknown`, no preset and no stored role of that name where it is read;
   * `reference`, the role or one it references names a role unknown at its home; `cycle`, the
   * references loop; `ambiguous`, two stored roles of one name are visible at one place; `preset`,
   * the name is a preset's; `taken`, a stored role of that name has its home along the same places.
   */
  ERR_AUTHZ_ROLE_INVALID: {
    role: string;
    reason: "unknown" | "reference" | "cycle" | "ambiguous" | "preset" | "taken";
    reference?: string;
  };
  /** The permission a question, a statement or a role names that the catalog does not declare. */
  ERR_AUTHZ_PERMISSION_UNKNOWN: { permission: string };
  /** The place that does not fit the structure the catalog declares. */
  ERR_AUTHZ_PLACE_OUTSIDE: { place: string };
  /**
   * What a question lacks: `empty`, it names no permission; `wildcard`, it names one, which only
   * statements and roles may.
   */
  ERR_AUTHZ_QUESTION_INVALID: { reason: "empty" | "wildcard" };
  /**
   * Why the author may not make the change, every reason at once: `not-manager`, the author does
   * not manage the place; `not-held`, the author does not hold what the statement gives or names,
   * is denied it under the place, or holds it for less time than the statement would last;
   * `about-self`, the statement is about the author; `last-manager`, the root would be left
   * without a permanent manager; `not-first`, the root already holds a permanent manager;
   * `ended`, the statement's end is not in the future.
   */
  ERR_AUTHZ_CHANGE_REFUSED: {
    reasons: ("not-manager" | "not-held" | "about-self" | "last-manager" | "not-first" | "ended")[];
  };
}

/** An OAuth 2.0 error response (RFC 6749 §4.1.2.1, §5.2). */
export interface OAuthErrorResponse {
  error: string;
  error_description?: string;
  error_uri?: string;
}

/** Options for {@link UnauthError}. */
export interface UnauthErrorOptions {
  /** The failure underneath, or the structured context listed in {@link UnauthErrorCauseMap}. */
  cause?: unknown;
  /** The HTTP status to answer with, a hint; unauth uses 400, 401, 403, 421, 500 and 502. */
  status?: number;
}

/**
 * Every error unauth throws. `message` carries no oracle: why a sign-in or a flow failed is in
 * `cause`.
 *
 * @example
 * try {
 *   return await completeFlow(provider, request, options);
 * } catch (error) {
 *   if (isUnauthError(error, "ERR_AUTHN_FLOW_EXPIRED")) return redirect("/login");
 *   throw error;
 * }
 */
export class UnauthError<TCode extends UnauthErrorCode = UnauthErrorCode> extends Error {
  readonly code: TCode;
  override readonly cause?: unknown;
  readonly status?: number;

  constructor(message: string, code: TCode, options?: UnauthErrorOptions) {
    super(message);
    this.name = "UnauthError";
    this.code = code;
    this.cause = options?.cause;
    this.status = options?.status;
  }
}

/**
 * Narrows `error` to an {@link UnauthError}, of `code` when given. A code listed in
 * {@link UnauthErrorCauseMap} also types `cause`.
 */
export function isUnauthError<T extends keyof UnauthErrorCauseMap>(
  error: unknown,
  code: T,
): error is UnauthError<T> & { cause: UnauthErrorCauseMap[T] };
export function isUnauthError<T extends KnownUnauthErrorCode>(
  error: unknown,
  code: T,
): error is UnauthError<T>;
export function isUnauthError(error: unknown): error is UnauthError;
export function isUnauthError(error: unknown, code?: string): boolean {
  if (!(error instanceof UnauthError)) return false;
  return code === undefined || error.code === code;
}
