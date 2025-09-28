import { type JWTClaims, encrypt } from "unjwt/jwe";
import { computeExpiresInSeconds } from "unjwt/utils";
import { secureCompare } from "unsecure";

import type {
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

export type BuildAuthorizationCodeReturn = string;

export interface BuildAuthorizationRedirectArgs {
  res: AuthorizeResponse | undefined;
  redirect_uri: string;
}

// #endregion type definitions

// #region internal functions

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

function validateAuthorizeRequest(req: AuthorizeRequest, iss: string): void {
  if (!isAuthorizationCodeRequest(req)) {
    throw new OAuthError({
      error: "invalid_request",
      error_description: "Invalid authorize request",
      state:
        "state" in req && typeof (req as AuthorizeRequest).state === "string"
          ? (req as AuthorizeRequest).state
          : undefined,
    });
  }

  const state = req.state;

  if (req.response_type !== "code") {
    throw new OAuthError({
      error: "unsupported_response_type",
      error_description: `Unsupported response_type: ${req.response_type}`,
      state,
      iss,
    });
  }

  // PKCE is required
  if (!req.code_challenge) {
    throw new OAuthError({
      error: "invalid_request",
      error_description: "Missing code_challenge (PKCE)",
      state,
      iss,
    });
  }

  if (
    req.code_challenge_method !== "plain" &&
    req.code_challenge_method !== "S256"
  ) {
    throw new OAuthError({
      error: "invalid_request",
      error_description: "Unsupported code_challenge_method",
      state,
      iss,
    });
  }

  if (
    !req.resource ||
    (Array.isArray(req.resource) && req.resource.length === 0)
  ) {
    throw new OAuthError({
      error: "invalid_request",
      error_description: "Missing resource in authorization request",
      state,
      iss,
    });
  }
}

/**
 * Build redirect URI with either ?code= or ?error= fragment/query params as per OAuth 2.1
 * Note: OAuth 2.1 uses query component for authorization code; we preserve given state.
 */
export function buildAuthorizationRedirect(
  args: BuildAuthorizationRedirectArgs,
): string {
  const { res, redirect_uri } = args;
  if (!redirect_uri) {
    throw new OAuthError({
      error: "invalid_request",
      error_description: "Missing redirect_uri for authorization redirect",
      iss: res?.iss,
      state: res?.state,
    });
  }

  const url = new URL(redirect_uri);
  const params = url.searchParams;
  if (res?.iss) {
    params.set("iss", res.iss);
  }

  if (!res) {
    params.set("error", "server_error");
    params.set("error_description", "Unknown error");
    return url.toString();
  }

  if ("code" in res) {
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

// #endregion internal functions

// #region runtime functions

export function validateRedirectUri(
  req: {
    redirectUri?: string | undefined;
    state?: string;
  },
  registeredRedirectUris: string | string[],
  iss?: string | undefined,
): string | AuthorizeErrorResponse {
  const { redirectUri, state } = req;
  const uris = Array.isArray(registeredRedirectUris)
    ? registeredRedirectUris
    : [registeredRedirectUris];

  // If no redirect URI is requested, and only one is registered, use that one.
  if (!redirectUri) {
    if (uris.length > 1) {
      return new OAuthError({
        error: "invalid_request",
        error_description: "Missing redirect_uri in request",
        state: state,
        iss: iss,
      }).toJSON();
    } else if (uris.length === 1 && uris[0]) {
      return uris[0];
    } else {
      return new OAuthError({
        error: "invalid_request",
        error_description: "No redirect URIs registered for this client",
        state: state,
        iss: iss,
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
    state: state,
    iss: iss,
  }).toJSON();
}

export async function buildAuthorizationCode(
  args: BuildAuthorizationCodeArgs,
): Promise<BuildAuthorizationCodeReturn> {
  const { req, claims, iss, options } = args;

  let code: string | undefined = undefined;
  let error: AuthorizeErrorResponse | undefined = undefined;
  try {
    validateAuthorizeRequest(req, iss);

    if (!("sub" in claims) || typeof claims.sub !== "string" || !claims.sub) {
      throw new OAuthError({
        error: "invalid_request",
        error_description:
          "Missing subject (sub) for end-user in authorization request",
        state: req.state,
        iss,
      });
    }

    const opts = authorizationCodeDefaults(options);

    const randomJti = args.randomJti || crypto.randomUUID;
    const currentDate =
      (args.currentDate || opts.encryptOptions.currentDate) ?? new Date();
    const iat = Math.floor(currentDate.getTime() / 1000);

    code = await encrypt(
      {
        ...claims,
        jti: randomJti(),
        iss,
        iat,
        exp: iat + computeExpiresInSeconds(opts.encryptOptions.expiresIn),
        client_id: req.client_id,
        redirect_uri: req.redirect_uri,
        code_challenge: req.code_challenge,
        // OAuth 2.1 clients are supposed to use S256, but plain is used for backwards compatibility
        code_challenge_method: req.code_challenge_method || "plain",
        // Persist resource indicators so the token endpoint can translate them to aud
        resource: req.resource,
        ...(req.scope ? { scope: req.scope } : {}),
      },
      opts.privateKey,
      {
        ...opts.encryptOptions,
        protectedHeader: {
          ...opts.encryptOptions?.protectedHeader,
          typ: "ac+jwt",
        },
        currentDate,
      },
    );
  } catch (error_) {
    error =
      error_ instanceof OAuthError
        ? error_.toJSON()
        : new OAuthError({
            error: "server_error",
            error_description:
              (error_ as Error)?.message ||
              "Failed to generate authorization code",
            state: req.state,
            iss,
            cause: error_,
          }).toJSON();
  }

  return buildAuthorizationRedirect({
    res: code ? { code, iss, state: req.state } : error,
    redirect_uri: req.redirect_uri,
  });
}

// #endregion functions
