// #region Generic Error

export type GenericErrorCode =
  // The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.
  | "invalid_request"
  // The client is not authorized to request an authorization code using this method or to use this authorization grant type.
  | "unauthorized_client"
  // The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner.
  | "invalid_scope";

// #endregion

// #region Authorization Error

export type AuthorizationErrorCode =
  | GenericErrorCode
  // The resource owner or authorization server denied the request.
  | "access_denied"
  // The authorization server does not support obtaining an authorization code using this method.
  | "unsupported_response_type"
  // The authorization server encountered an unexpected condition that prevented it from fulfilling the request. (This error code is needed because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.)
  | "server_error"
  // The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server. (This error code is needed because a 503 Service Unavailable HTTP status code cannot be returned to the client via an HTTP redirect.)
  | "temporarily_unavailable";

/**
 * Interface for the query parameters of an error redirect response
 * from the Authorization Endpoint.
 */
export interface AuthorizationErrorResponse {
  error: AuthorizationErrorCode | (string & {});
  error_description?: string;
  error_uri?: string;
  state?: string;
  iss?: string;
}

// #endregion

// #region Token Error

export type TokenErrorCode =
  | GenericErrorCode
  // Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The authorization server MAY return an HTTP 401 (Unauthorized) status code to indicate which HTTP authentication schemes are supported. If the client attempted to authenticate via the Authorization request header field, the authorization server MUST respond with an HTTP 401 (Unauthorized) status code and include the WWW-Authenticate response header field matching the authentication scheme used by the client.
  | "invalid_client"
  // The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirect URI used in the authorization request, or was issued to another client.
  | "invalid_grant"
  // The authorization grant type is not supported by the authorization server.
  | "unsupported_grant_type";

/**
 * Interface for an error JSON response from the Token Endpoint.
 */
export interface TokenErrorResponse {
  error: TokenErrorCode | (string & {});
  error_description?: string;
  error_uri?: string;
}

// #endregion

// #region Token Revocation Error

export type TokenRevocationErrorCode =
  | TokenErrorCode
  // The authorization server does not support the revocation of the presented token type. That is, the client tried to revoke an access token on a server not supporting this feature.
  | "unsupported_token_type";

/**
 * Interface for an error JSON response from the Revocation Endpoint.
 */
export interface TokenRevocationErrorResponse {
  error: TokenRevocationErrorCode | (string & {});
  error_description?: string;
  error_uri?: string;
}

// #endregion

// #region Resource Error

export type ResourceErrorCode =
  | Extract<GenericErrorCode, "invalid_request">
  // The access token provided is expired, revoked, malformed, or invalid for other reasons. The resource server SHOULD respond with the HTTP 401 (Unauthorized) status code. The client MAY request a new access token and retry the protected resource request.
  | "invalid_token"
  // The request requires higher privileges (scopes) than provided by the scopes granted to the client and represented by the access token. The resource server SHOULD respond with the HTTP 403 (Forbidden) status code and MAY include the scope attribute with the scope necessary to access the protected resource.
  | "insufficient_scope";

/**
 * Interface for an error JSON response from a Protected Resource.
 */
export interface ResourceErrorResponse {
  error: ResourceErrorCode | (string & {});
  error_description?: string;
  realm?: string;
}

// #endregion

// #region Introspection Error

export type IntrospectionErrorCode = Exclude<
  ResourceErrorCode,
  "insufficient_scope"
>;

/**
 * Interface for an error JSON response from the Introspection Endpoint.
 */
export interface IntrospectionErrorResponse {
  error: IntrospectionErrorCode | (string & {});
  error_description?: string;
  error_uri?: string;
}

// #endregion

// #region OAuth Error

export type OAuthErrorDetails =
  | AuthorizationErrorResponse
  | TokenErrorResponse
  | TokenRevocationErrorResponse
  | ResourceErrorResponse
  | IntrospectionErrorResponse;

/**
 * OAuthError
 *
 * Lightweight error class for OAuth endpoint responses.
 * This class intentionally does not model HTTP transport; it only
 * models OAuth structured error payloads as defined by RFCs.
 */
export class OAuthError extends Error {
  override get name(): string {
    return "OAuthError";
  }

  /**
   * The OAuth error code (e.g. "invalid_request", "invalid_grant").
   */
  readonly error: string;

  /**
   * Human-readable ASCII text description of the error.
   */
  readonly error_description?: string;

  /**
   * URI identifying a human-readable web page with information about the error.
   */
  readonly error_uri?: string;

  /**
   * Optional state parameter (used by Authorization Endpoint).
   */
  readonly state?: string;

  /**
   * Optional realm (used by Resource servers).
   */
  readonly realm?: string;

  /**
   * Optional issuer identifier (used by Authorization responses in this codebase).
   */
  readonly iss?: string;

  /**
   * Optional underlying cause.
   */
  override readonly cause?: unknown;

  constructor(
    error: string,
    details?: OAuthErrorDetails | (Error & { cause?: unknown }),
  );
  constructor(details: OAuthErrorDetails | (Error & { cause?: unknown }));
  constructor(
    arg1: string | OAuthErrorDetails | (Error & { cause?: unknown }),
    arg2?: OAuthErrorDetails | (Error & { cause?: unknown }),
  ) {
    let errorInput: string | undefined;
    let details: OAuthErrorDetails | (Error & { cause?: unknown }) | undefined;
    if (typeof arg1 === "string") {
      errorInput = arg1;
      details = arg2;
    } else {
      details = arg1;
    }

    const errorCode =
      (details as OAuthErrorDetails)?.error ||
      ((details as Error)?.cause as OAuthErrorDetails)?.error ||
      "invalid_request";

    const errorDescription =
      errorInput ||
      (details as OAuthErrorDetails)?.error_description ||
      ((details as Error)?.cause as OAuthErrorDetails)?.error_description;

    const error: string = ["OAuthError", errorCode, errorDescription]
      .filter(Boolean)
      .join(" ");

    // @ts-ignore https://v8.dev/features/error-cause
    super(error, { cause: details });
    this.cause = details;
    Error.captureStackTrace?.(this, this.constructor);

    this.error = errorCode;
    this.error_description = errorDescription;
    this.error_uri =
      details && "error_uri" in details ? details.error_uri : undefined;
    this.state = details && "state" in details ? details.state : undefined;
    this.realm = details && "realm" in details ? details.realm : undefined;
    this.iss = details && "iss" in details ? details.iss : undefined;
  }

  static override isError(input: any): input is OAuthError {
    return input instanceof Error && input?.name === "OAuthError";
  }

  /**
   * Serialize to the OAuth error response shape appropriate for endpoints.
   * Only includes properties that are present.
   */
  toJSON(): OAuthErrorDetails {
    const out: OAuthErrorDetails = { error: this.error };
    if (this.error_description) out.error_description = this.error_description;
    if (this.error_uri)
      (
        out as
          | AuthorizationErrorResponse
          | TokenErrorResponse
          | TokenRevocationErrorResponse
          | IntrospectionErrorResponse
      ).error_uri = this.error_uri;
    if (this.state) (out as AuthorizationErrorResponse).state = this.state;
    if (this.iss) (out as AuthorizationErrorResponse).iss = this.iss;
    if (this.realm) (out as ResourceErrorResponse).realm = this.realm;
    return out;
  }

  // Convenience factories

  static forAuthorization(err: AuthorizationErrorResponse) {
    return new OAuthError(err);
  }

  static forToken(err: TokenErrorResponse) {
    return new OAuthError(err);
  }

  static forRevocation(err: TokenRevocationErrorResponse) {
    return new OAuthError(err);
  }

  static forResource(err: ResourceErrorResponse) {
    return new OAuthError(err);
  }

  static forIntrospection(err: IntrospectionErrorResponse) {
    return new OAuthError(err);
  }
}

// #endregion
