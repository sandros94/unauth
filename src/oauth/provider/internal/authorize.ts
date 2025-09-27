import { type JWTClaims, encrypt } from "unjwt/jwe";
import { secureCompare } from "unsecure";

import type {
  AuthorizationCodeClaims,
  AuthorizeRequest,
  AuthorizeErrorResponse,
  AuthorizeResponse,
} from "../../types";

import { OAuthError } from "../error";
import {
  type AuthorizationCodeOptions,
  authorizationCodeDefaults,
} from "./defaults";

// #region type definitions

export interface BuildAuthorizationCodeArgs {
  req: AuthorizeRequest;
  /**
   * Claims to include in the authorization code.
   */
  claims: JWTClaims & { sub: string };
  /**
   * Issuer to include in error responses (if any).
   */
  iss: string;
  options: AuthorizationCodeOptions;
  /**
   * A function to generate a unique identifier for tokens.
   */
  randomJti?: () => string;
  /**
   * Date to use when computing NumericDate claims, defaults to `new Date()`.
   */
  currentDate?: Date;
}

export type BuildAuthorizationCodeReturn =
  | AuthorizeErrorResponse
  | {
      res: AuthorizeResponse;
      claims: AuthorizationCodeClaims;
    };

export interface BuildAuthorizationRedirectArgs {
  res: AuthorizeResponse;
  redirect_uri: string;
  iss: string;
}

// #endregion type definitions

// #region runtime validation functions

function isAuthorizationCodeRequest(value: unknown): value is AuthorizeRequest {
  if (typeof value !== "object" || value == null) return false;
  const v = value as AuthorizeRequest;
  return (
    typeof v.client_id === "string" &&
    typeof v.response_type === "string" &&
    typeof v.code_challenge === "string" &&
    (v.redirect_uri === undefined || typeof v.redirect_uri === "string") &&
    (v.state === undefined || typeof v.state === "string") &&
    (v.scope === undefined || typeof v.scope === "string") &&
    (v.code_challenge_method === undefined ||
      typeof v.code_challenge_method === "string")
  );
}

function validateAuthorizeRequest(
  req: AuthorizeRequest,
  iss: string,
): AuthorizeErrorResponse | undefined {
  if (!isAuthorizationCodeRequest(req)) {
    return new OAuthError({
      error: "invalid_request",
      error_description: "Invalid authorize request",
      state:
        "state" in req && typeof (req as AuthorizeRequest).state === "string"
          ? (req as AuthorizeRequest).state
          : undefined,
    }).toJSON();
  }

  const state = req.state;

  if (req.response_type !== "code") {
    return new OAuthError({
      error: "unsupported_response_type",
      error_description: `Unsupported response_type: ${req.response_type}`,
      state,
      iss,
    }).toJSON();
  }

  // PKCE is required
  if (!req.code_challenge) {
    return new OAuthError({
      error: "invalid_request",
      error_description: "Missing code_challenge (PKCE)",
      state,
      iss,
    }).toJSON();
  }

  if (
    req.code_challenge_method !== "plain" &&
    req.code_challenge_method !== "S256"
  ) {
    return new OAuthError({
      error: "invalid_request",
      error_description: "Unsupported code_challenge_method",
      state,
      iss,
    }).toJSON();
  }

  if (
    !req.resource ||
    (Array.isArray(req.resource) && req.resource.length === 0)
  ) {
    return new OAuthError({
      error: "invalid_request",
      error_description: "Missing resource in authorization request",
      state,
      iss,
    }).toJSON();
  }

  return undefined;
}

export function validateAuthorizeRedirectUri(
  redirectUri: string | undefined,
  registeredRedirectUris: string | string[],
  options: { iss: string; state?: string },
): string | AuthorizeErrorResponse {
  const uris = Array.isArray(registeredRedirectUris)
    ? registeredRedirectUris
    : [registeredRedirectUris];

  // If no redirect URI is requested, and only one is registered, use that one.
  if (!redirectUri) {
    if (uris.length > 1) {
      return new OAuthError({
        error: "invalid_request",
        error_description: "Missing redirect_uri in request",
        state: options.state,
        iss: options.iss,
      }).toJSON();
    } else if (uris.length === 1 && uris[0]) {
      return uris[0];
    } else {
      return new OAuthError({
        error: "invalid_request",
        error_description: "No redirect URIs registered for this client",
        state: options.state,
        iss: options.iss,
      }).toJSON();
    }
  }

  // If a redirect URI is requested, it must exactly match one of the registered URIs via `secureCompare`.
  for (const uri of uris) {
    // We use the requested redirectUri as the time constant comparison input to avoid leaking
    if (secureCompare(redirectUri, uri)) {
      return redirectUri;
    }
  }

  return new OAuthError({
    error: "invalid_request",
    error_description: "Invalid redirect_uri",
    state: options.state,
    iss: options.iss,
  }).toJSON();
}

// #endregion runtime validation functions

// #region runtime implementation functions

export async function buildAuthorizationCode(
  args: BuildAuthorizationCodeArgs,
): Promise<BuildAuthorizationCodeReturn> {
  const { req, claims, iss, options } = args;
  const validationError = validateAuthorizeRequest(req, iss);

  if (validationError) {
    return validationError;
  }
  if (!("sub" in claims) || typeof claims.sub !== "string" || !claims.sub) {
    return new OAuthError({
      error: "invalid_request",
      error_description:
        "Missing subject (sub) for end-user in authorization request",
      state: req.state,
      iss,
    }).toJSON() as AuthorizeErrorResponse;
  }

  const opts = authorizationCodeDefaults(options);

  const randomJti = args.randomJti || crypto.randomUUID;
  const currentDate =
    (args.currentDate || opts.encryptOptions.currentDate) ?? new Date();
  const iat = Math.floor(currentDate.getTime() / 1000);

  const acClaims: AuthorizationCodeClaims = {
    ...claims,
    jti: randomJti(),
    iss,
    iat,
    exp: iat + opts.encryptOptions.expiresIn,
    client_id: req.client_id,
    redirect_uri: req.redirect_uri,
    code_challenge: req.code_challenge,
    // OAuth 2.1 clients are supposed to use S256, but plain is used for backwards compatibility
    code_challenge_method: req.code_challenge_method || "plain",
    // Persist resource indicators so the token endpoint can translate them to aud
    resource: req.resource,
    ...(req.scope ? { scope: req.scope } : {}),
  };

  const code = await encrypt(claims, opts.privateKey, {
    ...opts.encryptOptions,
    protectedHeader: {
      ...opts.encryptOptions?.protectedHeader,
      typ: "ac+jwt",
    },
    currentDate,
  }).catch((error_) => {
    return new OAuthError({
      error: "server_error",
      error_description: "Failed to generate authorization code",
      state: req.state,
      iss,
      cause: error_,
    }).toJSON() as AuthorizeErrorResponse;
  });

  return typeof code === "string"
    ? {
        res: {
          code,
          iss,
          state: req.state,
        },
        claims: acClaims,
      }
    : code;
}

/**
 * Build redirect URI with either ?code= or ?error= fragment/query params as per OAuth 2.1
 * Note: OAuth 2.1 uses query component for authorization code; we preserve given state.
 */
export function buildAuthorizationRedirect(
  args: BuildAuthorizationRedirectArgs,
): string | AuthorizeErrorResponse {
  const { res, iss, redirect_uri } = args;
  if (!redirect_uri) {
    return new OAuthError({
      error: "invalid_request",
      error_description: "Missing redirect_uri for authorization response",
      iss,
      state: res.state,
    }).toJSON();
  }

  const url = new URL(redirect_uri);
  const params = url.searchParams;
  params.set("iss", iss);

  if (!("code" in res) && !("error" in res)) {
    return new OAuthError({
      error: "server_error",
      error_description: "Invalid authorization result",
      iss,
    }).toJSON();
  } else if ("code" in res) {
    params.set("code", res.code);
    if (res.state) params.set("state", res.state);
  } else {
    params.set("error", res.error);
    if (res.error_description)
      params.set("error_description", res.error_description);
    if (res.state) params.set("state", res.state);
  }

  url.search = params.toString();
  return url.toString();
}

// #endregion runtime functions
