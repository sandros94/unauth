/**
 * The error codes unauth itself throws.
 *
 * - `ERR_AUTHN_*`: authentication (`unauth/n`).
 * - `ERR_UNAUTH_*`: misconfiguration, whatever the entry.
 *   `_ROLE_UNKNOWN`, `_ROLE_REACH` and `_BOOTSTRAP_CLOSED` are reserved for permission management.
 *
 * Use this type where a typo must not compile: {@link isUnauthError} takes it.
 */
export type KnownUnauthErrorCode =
  | "ERR_UNAUTH_CONFIG_INVALID" // a configuration that cannot work
  // authn (`unauth/n`)
  | "ERR_AUTHN_UNAUTHENTICATED" // reserved for the `unauth/session` guard: no signed-in session
  | "ERR_AUTHN_LOGIN_REQUIRED" // the provider needs to know which account signs in (`login`)
  | "ERR_AUTHN_LOGIN_INVALID" // `login` names no usable account at the provider
  | "ERR_AUTHN_FLOW_EXPIRED" // no sign-in flow to complete: never started, expired or already used
  | "ERR_AUTHN_STATE_MISMATCH" // the callback does not belong to the flow this browser started
  | "ERR_AUTHN_PROVIDER_REFUSED" // the provider answered the authorization request with an error
  | "ERR_AUTHN_TOKEN_EXCHANGE" // the token endpoint refused or failed a code or refresh grant
  | "ERR_AUTHN_ID_TOKEN_INVALID" // an id_token failed verification
  | "ERR_AUTHN_PROFILE_INVALID" // the provider's account data does not name a usable identity
  | "ERR_AUTHN_PROVIDER_ERROR" // a provider endpoint failed or answered unusably
  | "ERR_AUTHN_TOKEN_INVALID" // a one-time token is malformed, forged or expired
  | "ERR_AUTHN_TOKEN_PURPOSE" // a one-time token was issued for another purpose
  | "ERR_AUTHN_TOKEN_USED"; // a one-time token was already used

/**
 * An {@link UnauthError} `code`: every {@link KnownUnauthErrorCode}, plus any other string, so a
 * newer unauth or an application's own `UnauthError` may carry a code this version does not list.
 */
export type UnauthErrorCode = KnownUnauthErrorCode | (string & {});

/**
 * The structured `cause` of the codes that carry one. Codes absent here have an `unknown` cause,
 * usually the error underneath.
 */
export interface UnauthErrorCauseMap {
  /**
   * Why the callback carries no flow: `missing`, no flow cookie came back at all (the sign-in
   * started on another host, or cookies are off); `unreadable`, the cookie expired or does not
   * open; `consumed`, the flow store no longer has the record.
   */
  ERR_AUTHN_FLOW_EXPIRED: { reason: "missing" | "unreadable" | "consumed" };
  /**
   * The error the provider answered the authorization request with: at the redirect URI (RFC 6749
   * §4.1.2.1) or at the pushed authorization request endpoint (RFC 9126 §2.3).
   */
  ERR_AUTHN_PROVIDER_REFUSED: OAuthErrorResponse;
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
   * `malformed`, an answer that is not what its protocol says; `failed`, a custom provider's own
   * leg threw something that is not an `UnauthError`. `status` is the HTTP status once one
   * arrived, `cause` the failure underneath when there is one.
   */
  ERR_AUTHN_PROVIDER_ERROR: {
    reason: "unreachable" | "timeout" | "too-large" | "status" | "malformed" | "failed";
    status?: number;
    cause?: unknown;
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
  /** HTTP status a framework glue answers with (400, 401, 403, 409, 500, 502); a hint, never the mechanism. */
  status?: number;
}

/**
 * Every error unauth throws. Messages shown to users carry no oracle: why a sign-in or a flow
 * failed lives in `cause`, not in `message`.
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
