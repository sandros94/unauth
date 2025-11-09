import { computeExpiresInSeconds } from "unjwt/utils";
import { secureCompare } from "unsecure";
import { encrypt } from "unjwt/jwe";

import type {
  AuthorizeRequest,
  AuthorizationCodeClaims,
  Result,
} from "../../types";

import {
  type AuthorizeErrorCode,
  type AuthorizeErrorResponse,
  OAuthError,
} from "../error";
import {
  type AuthorizationCodeOptions,
  authorizationCodeDefaults,
} from "./defaults";

// #region types

export interface NormalizedAuthorizeInput {
  client_id: string;
  subject: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: "S256" | "plain";
  resource: string | string[];
  scope?: string;
  state?: string;
  acExtraClaims?: Record<string, unknown>;
}

export type ValidateAuthorizeRequestResult = Result<
  Omit<NormalizedAuthorizeInput, "subject" | "redirect_uri"> & {
    redirect_uri?: string;
  },
  undefined,
  AuthorizeErrorResponse
>;

export interface IssueAuthorizationCodeOptions {
  iss: string;
  authorizationCodeOptions: AuthorizationCodeOptions;
  /**
   * A function to generate a unique identifier for tokens.
   */
  randomJti?: () => string;
  /**
   * Date to use when computing NumericDate claims, defaults to `new Date()`.
   */
  currentDate?: Date;
}

export type IssueAuthorizationCodeReturn = Result<
  string,
  AuthorizationCodeClaims,
  AuthorizeErrorResponse
>;

// #endregion types

// #region internals

function authorizeError(
  code: AuthorizeErrorCode | (string & {}),
  description: string,
  details: Omit<AuthorizeErrorResponse, "error" | "error_description"> & {
    cause?: unknown;
  } = {},
): AuthorizeErrorResponse {
  return new OAuthError({
    ...details,
    error: code,
    error_description: description,
  }).toJSON();
}

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

// #endregion internals

// #region validations

export function validateRedirectUri(
  redirect_uri: string | undefined,
  allowedRedirectUris: string | string[],
  errorDetails?: Omit<AuthorizeErrorResponse, "error" | "error_description">,
): Result<string, undefined, AuthorizeErrorResponse> {
  const uris = Array.isArray(allowedRedirectUris)
    ? allowedRedirectUris
    : [allowedRedirectUris];

  // If no redirect URI is requested, and only one is allowed, use that one.
  if (!redirect_uri) {
    if (uris.length > 1) {
      return {
        success: false,
        error: authorizeError(
          "invalid_request",
          "Missing redirect_uri in request",
          errorDetails,
        ),
      };
    } else if (uris.length === 1 && uris[0]) {
      return {
        success: true,
        value: uris[0],
      };
    } else {
      return {
        success: false,
        error: authorizeError(
          "invalid_request",
          "No redirect URIs registered for this client",
          errorDetails,
        ),
      };
    }
  }

  // If a redirect URI is requested, it must exactly match one of the registered URIs via `secureCompare`.
  for (const uri of uris) {
    // We use the requested redirect_uri as the time constant comparison input to avoid leaking
    if (secureCompare(redirect_uri, uri)) {
      return {
        success: true,
        value: uri,
      };
    }
  }

  return {
    success: false,
    error: authorizeError(
      "invalid_request",
      "Invalid redirect_uri",
      errorDetails,
    ),
  };
}

export function validateAuthorizeRequest(
  req: AuthorizeRequest,
  errorDetails?: Omit<AuthorizeErrorResponse, "error" | "error_description">,
): ValidateAuthorizeRequestResult {
  if (!isAuthorizationCodeRequest(req)) {
    return {
      success: false,
      error: authorizeError("invalid_request", "Invalid authorize request", {
        ...errorDetails,
        state:
          "state" in req && typeof (req as AuthorizeRequest).state === "string"
            ? (req as AuthorizeRequest).state
            : undefined,
      }),
    };
  }

  if (req.response_type !== "code") {
    return {
      success: false,
      error: authorizeError(
        "unsupported_response_type",
        `Unsupported response_type: ${req.response_type}`,
        {
          ...errorDetails,
          state: req.state,
        },
      ),
    };
  }

  if (!req.client_id) {
    return {
      success: false,
      error: authorizeError(
        "invalid_request",
        "Missing client_id in authorization request",
        errorDetails,
      ),
    };
  }

  // PKCE is required
  if (!req.code_challenge) {
    return {
      success: false,
      error: authorizeError(
        "invalid_request",
        "Missing code_challenge (PKCE)",
        {
          ...errorDetails,
          state: req.state,
        },
      ),
    };
  }

  if (
    req.code_challenge_method !== "plain" &&
    req.code_challenge_method !== "S256"
  ) {
    return {
      success: false,
      error: authorizeError(
        "invalid_request",
        "Unsupported code_challenge_method",
        {
          ...errorDetails,
          state: req.state,
        },
      ),
    };
  }

  if (
    !req.resource ||
    (Array.isArray(req.resource) && req.resource.length === 0)
  ) {
    return {
      success: false,
      error: authorizeError(
        "invalid_request",
        "Missing resource in authorization request",
        {
          ...errorDetails,
          state: req.state,
        },
      ),
    };
  }

  const {
    response_type: _rt,
    redirect_uri, // This should be validated separately
    client_id,
    code_challenge,
    code_challenge_method,
    resource,
    scope,
    state,
    ...acExtraClaims
  } = req;

  return {
    success: true,
    value: {
      redirect_uri,
      client_id,
      code_challenge,
      code_challenge_method,
      resource,
      scope,
      state,
      acExtraClaims,
    },
  };
}

// #endregion validations

// #region runtime

/**
 * Build redirect URI with either ?code= or ?error= fragment/query params as per OAuth 2.1
 * Note: OAuth 2.1 uses query component for authorization code; we preserve given state.
 */
export function buildAuthorizationRedirect(
  redirect_uri: string,
  code: string | undefined,
  errorDetails: AuthorizeErrorResponse | undefined,
  state: string | undefined,
  iss: string | undefined,
): Result<string, AuthorizeErrorResponse, AuthorizeErrorResponse> {
  if (!redirect_uri) {
    return {
      success: false,
      error: authorizeError(
        "invalid_request",
        "Missing redirect_uri for authorization redirect",
        errorDetails,
      ),
    };
  }

  const url = new URL(redirect_uri);
  const params = url.searchParams;
  if (iss) {
    params.set("iss", iss);
  }
  if (state) {
    params.set("state", state);
  }

  if (code) {
    params.set("code", code);

    url.search = params.toString();
    return {
      success: true,
      value: url.toString(),
    };
  } else {
    const error = errorDetails?.error || "server_error";
    const error_description =
      errorDetails?.error_description || "Unknown error";
    params.set("error", error);
    params.set("error_description", error_description);

    url.search = params.toString();
    return {
      success: true,
      value: url.toString(),
      warnings: authorizeError(error, error_description, errorDetails),
    };
  }
}

export async function issueAuthorizationCode(
  args: NormalizedAuthorizeInput,
  options: IssueAuthorizationCodeOptions,
): Promise<IssueAuthorizationCodeReturn> {
  const {
    client_id,
    subject,
    redirect_uri,
    code_challenge,
    code_challenge_method,
    resource,
    state,
    scope,
    acExtraClaims,
  } = args;
  const { iss, authorizationCodeOptions } = options;

  if (!redirect_uri) {
    return {
      success: false,
      error: authorizeError(
        "invalid_request",
        "Missing redirect_uri for authorization redirect",
        {
          state,
          iss,
        },
      ),
    };
  }

  if (!subject) {
    return {
      success: false,
      error: authorizeError(
        "invalid_request",
        "Missing subject (sub) for end-user in authorization request",
        {
          state,
          iss,
        },
      ),
    };
  }

  if (!client_id || !code_challenge || !resource) {
    // This should have been caught in validation, throwing as a last resort
    throw new OAuthError({
      error: "invalid_request",
      error_description: `Missing required parameters in authorization request: ${[client_id ? "" : "client_id", code_challenge ? "" : "code_challenge", resource ? "" : "resource"].filter(Boolean).join(", ")}`,
      state,
      iss,
    });
  }

  const opts = authorizationCodeDefaults(authorizationCodeOptions);
  let error: (AuthorizeErrorResponse & { cause?: unknown }) | undefined =
    undefined;
  const randomJti = options.randomJti || crypto.randomUUID;
  const currentDate =
    (options.currentDate || opts.encryptOptions.currentDate) ?? new Date();

  const iat = Math.floor(currentDate.getTime() / 1000);
  const claims = {
    ...acExtraClaims,
    sub: subject,
    jti: randomJti(),
    iss,
    iat,
    exp: iat + computeExpiresInSeconds(opts.encryptOptions.expiresIn),
    client_id,
    redirect_uri,
    code_challenge,
    // OAuth 2.1 clients are supposed to use S256, but plain is used for backwards compatibility
    code_challenge_method: code_challenge_method || "S256",
    // Persist resource indicators so the token endpoint can translate them to aud
    resource,
    ...(scope ? { scope } : {}),
  };
  const code = await encrypt(claims, opts.privateKey, {
    ...opts.encryptOptions,
    protectedHeader: {
      ...opts.encryptOptions?.protectedHeader,
      typ: "ac+jwt",
    },
    currentDate,
  }).catch((error_) => {
    error = authorizeError(
      "server_error",
      "Failed to generate authorization code",
      {
        state,
        iss,
        cause: error_,
      },
    );
    return undefined;
  });

  const redirect = buildAuthorizationRedirect(
    redirect_uri,
    code,
    error,
    state,
    iss,
  );

  return redirect.success
    ? {
        success: true,
        value: redirect.value,
        ...(code
          ? {
              artifacts: claims,
              warnings: undefined,
            }
          : {
              artifacts: undefined,
              warnings: redirect.warnings,
            }),
      }
    : redirect;
}

// #endregion functions
