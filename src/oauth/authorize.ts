import { encrypt } from "unjwt/jwe";
import type { JWK, JWEEncryptOptions, JWTClaims } from "unjwt";

import type { MaybePromise } from "../types/index";
import type { OAuthAuthorizationCodeClaims } from "./types";
import { normalizeScope } from "./utils";
import {
  type ResolvedAuthorizeOptions,
  DEFAULTS,
  withAuthorizeDefaults,
} from "./defaults";

/**
 * OAuth 2.1 Authorization Endpoint utilities
 * These helpers validate the authorization request, enforce PKCE, build the authorization code (JWE), and craft redirect URIs with code or error responses.
 */

export type OAuthResponseType = "code";

export interface OAuthAuthorizeRequestRequired {
  /**
   * only "code" (implicit removed by OAuth 2.1)
   */
  response_type: OAuthResponseType;
  client_id: string;
  /**
   * MUST be present in OAuth 2.1 (no discovery)
   */
  redirect_uri: string;
}

export interface OAuthAuthorizeRequestOptional {
  /**
   * The requested scope, space-delimited.
   */
  scope?: string;
  state?: string;
  /**
   * The code challenge for PKCE.
   */
  code_challenge?: string;
  /**
   * The code challenge method for PKCE.
   * Must be either "S256" or "plain".
   *
   * @default "plain"
   */
  code_challenge_method?: "S256" | "plain";
  // TODO: OIDC prompt/login_hint etc are out-of-scope for plain OAuth 2.1, but could be added by callers
}

export type OAuthAuthorizeRequest = OAuthAuthorizeRequestRequired &
  OAuthAuthorizeRequestOptional &
  Record<string, unknown>;

export interface OAuthAuthorizeOptions {
  /**
   * The issuer identifier.
   */
  issuer: string;
  /**
   * The secret or private key to sign the refresh token.
   */
  jweSecret: string | JWK;
  /**
   * Options for encrypting the refresh token.
   */
  encryptOptions?: JWEEncryptOptions;
  /**
   * A function to generate a unique identifier for tokens.
   */
  randomJti?: () => string;
  /**
   * The default authorization scope.
   */
  defaultScope?: string;
  /**
   * Allowed scopes configuration (optional). If provided, membership will be validated.
   */
  availableScopes?: string[];
}

export interface OAuthAuthorizeSuccess {
  /**
   * The authorization code (JWE) to be returned to the client.
   */
  code: string;
  state?: string;
}

export type OAuthAuthorizeErrorCode =
  | "invalid_request"
  | "unauthorized_client"
  | "access_denied"
  | "unsupported_response_type"
  | "invalid_scope"
  | "server_error"
  | "temporarily_unavailable";

export interface OAuthAuthorizeError {
  error: OAuthAuthorizeErrorCode;
  error_description?: string;
  state?: string;
}

export function isOAuthAuthorizeRequest(
  value: unknown,
): value is OAuthAuthorizeRequest {
  if (typeof value !== "object" || value == null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.response_type === "string" &&
    typeof v.client_id === "string" &&
    typeof v.redirect_uri === "string"
  );
}

export function assertAuthorizeRequest(
  req: unknown,
): asserts req is OAuthAuthorizeRequest {
  if (!isOAuthAuthorizeRequest(req)) {
    throw new OAuthAuthorizeException(
      "invalid_request",
      "Invalid authorize request",
    );
  }
}

export class OAuthAuthorizeException extends Error {
  constructor(
    public readonly error: OAuthAuthorizeErrorCode,
    message?: string,
  ) {
    super(message || error);
    this.name = "OAuthAuthorizeException";
  }
}

/** Enforce supported response_type=code only (OAuth 2.1) */
export function validateResponseType(rt: string): asserts rt is "code" {
  if (rt !== "code") {
    throw new OAuthAuthorizeException(
      "unsupported_response_type",
      `Unsupported response_type: ${rt}`,
    );
  }
}

/**
 * Create the authorization code (JWE) from request + cb-provided custom claims
 */
export async function buildAuthorizationCode(
  req: OAuthAuthorizeRequest,
  options: OAuthAuthorizeOptions,
  cb?: (
    req: OAuthAuthorizeRequest,
    opts: ResolvedAuthorizeOptions,
  ) => MaybePromise<
    Partial<JWTClaims> & {
      sub: string;
      scope?: string;
      client_id?: string;
    }
  >,
): Promise<OAuthAuthorizeSuccess> {
  assertAuthorizeRequest(req);
  validateResponseType(req.response_type);

  const resolved = withAuthorizeDefaults(options);
  const {
    issuer,
    jweSecret,
    encryptOptions,
    randomJti,
    defaultScope,
    availableScopes,
  } = resolved;

  // Scope
  const scope = normalizeScope(req.scope, defaultScope, availableScopes);

  // PKCE: Required for code flow
  if (!req.code_challenge) {
    throw new OAuthAuthorizeException(
      "invalid_request",
      "Missing code_challenge (PKCE)",
    );
  }
  const m = req.code_challenge_method || DEFAULTS.codeChallengeMethod;
  if (m !== "plain" && m !== "S256") {
    throw new OAuthAuthorizeException(
      "invalid_request",
      "Unsupported code_challenge_method",
    );
  }

  const extraClaims = cb
    ? await cb(req, resolved)
    : ({} as Partial<JWTClaims> & { sub: string });
  if (
    !("sub" in extraClaims) ||
    typeof extraClaims.sub !== "string" ||
    !extraClaims.sub
  ) {
    throw new OAuthAuthorizeException(
      "invalid_request",
      "Missing subject (sub) for end-user in authorization",
    );
  }

  const claims: Omit<OAuthAuthorizationCodeClaims, "iat"> = {
    jti: randomJti(),
    ...extraClaims,
    iss: issuer,
    scope,
    code_challenge: req.code_challenge,
    code_challenge_method: m,
    redirect_uri: req.redirect_uri,
  };

  const code = await encrypt(claims, jweSecret, encryptOptions);
  return { code, state: req.state };
}

/**
 * Build redirect URI with either ?code= or ?error= fragment/query params as per OAuth 2.1
 * Note: OAuth 2.1 uses query component for authorization code; we preserve given state.
 */
export function buildAuthorizeRedirect<T extends string | URL>(
  redirectUri: T,
  result: OAuthAuthorizeSuccess | OAuthAuthorizeError,
): T {
  const url = redirectUri instanceof URL ? redirectUri : new URL(redirectUri);
  const params = url.searchParams;
  if ("code" in result) {
    params.set("code", result.code);
    if (result.state) params.set("state", result.state);
  } else {
    params.set("error", result.error);
    if (result.error_description)
      params.set("error_description", result.error_description);
    if (result.state) params.set("state", result.state);
  }
  url.search = params.toString();
  return (redirectUri instanceof URL ? url : url.toString()) as T;
}

/** Helper for creating a standardized error payload, preserving state when present */
export function authorizeError(
  error: OAuthAuthorizeErrorCode,
  description?: string,
  state?: string,
): OAuthAuthorizeError {
  return { error, error_description: description, state };
}
