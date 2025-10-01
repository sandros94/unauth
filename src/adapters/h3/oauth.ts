import { computeExpiresInSeconds } from "unjwt/utils";
import type { CookieSerializeOptions } from "cookie-es";
import { createHooks } from "hookable";
import {
  type H3Event,
  createError,
  getQuery,
  readBody,
  getCookie,
  setCookie,
} from "h3";

import type { MaybePromise } from "../../types";

import {
  type Failure,
  type OAuthProviderOptions,
  type AccessTokenClaims,
  type RefreshTokenClaims,
  type AuthorizeRequest,
  type TokenRequest,
  type NormalizedAuthorizeInput,
  type IssueAuthorizationCodeReturn,
  type NormalizedTokenInput,
  type IssueTokenGrantReturn,
  type BuildOAuthDiscoveryArgs,
  OAuthProvider,
  validateRedirectUri as _coreValidateRedirectUri,
  buildOAuthDiscoveryDocument,
} from "../../core/oauth";

export interface OAuthHooks {
  authorizeRequest: (
    normalized: NormalizedAuthorizeInput,
    event: H3Event,
  ) => MaybePromise<void>;
  authorizeFailed: (
    error: Extract<IssueAuthorizationCodeReturn, Failure>,
    event: H3Event,
  ) => MaybePromise<void>;
  authorizeIssued: (
    acResult: Exclude<IssueAuthorizationCodeReturn, Failure>,
    event: H3Event,
  ) => MaybePromise<void>;
  tokenRequest: (
    normalized: NormalizedTokenInput,
    event: H3Event,
  ) => MaybePromise<void>;
  tokenFailed: (
    error: Extract<IssueTokenGrantReturn, Failure>,
    event: H3Event,
  ) => MaybePromise<void>;
  tokenIssued: (
    tokenGrant: Exclude<IssueTokenGrantReturn, Failure>,
    event: H3Event,
  ) => MaybePromise<void>;
  // TODO: introspection hooks?
}

export const oauthHooks = createHooks<OAuthHooks>();

const DEFAULT_AT_NAME = "access_token";
const DEFAULT_RT_NAME = "refresh_token";

let _oauthProvider: OAuthProvider | null = null;
export function useOAuthProvider(
  options: OAuthProviderOptions & {
    defaults?: {
      accessTokenName?: string;
      accessTokenCookieOptions?: CookieSerializeOptions;
      refreshTokenName?: string;
      refreshTokenCookieOptions?: CookieSerializeOptions;
    };
  },
) {
  const { defaults, ...opts } = options;
  const {
    accessTokenName = DEFAULT_AT_NAME,
    refreshTokenName = DEFAULT_RT_NAME,
  } = defaults || {};
  function getProvider() {
    if (!_oauthProvider) {
      _oauthProvider = new OAuthProvider(opts);
    }
    return _oauthProvider;
  }

  async function getAuthorizationCode(event: H3Event) {
    const req = await readBody<TokenRequest>(event).catch(() => undefined);
    return req &&
      "grant_type" in req &&
      req.grant_type === "authorization_code" &&
      typeof req.code === "string"
      ? getProvider()
          .introspectAuthorizationCode(req.code)
          .catch(() => null)
      : null;
  }
  async function getAccessToken(
    event: H3Event,
  ): Promise<AccessTokenClaims | null> {
    const context = ((event.context ||= Object.create(null)).unauth ||=
      Object.create(null));

    if (context?.[accessTokenName]) {
      return context[accessTokenName];
    }

    const at =
      event.headers.get("Authorization")?.split(" ")?.[1] ||
      getCookie(event, accessTokenName);
    if (!at) return null;

    const claims = await getProvider()
      .introspectAccessToken(at)
      .catch(() => null);
    if (!claims) return null;

    context[accessTokenName] = claims;
    return claims;
  }
  async function getRefreshToken(
    event: H3Event,
  ): Promise<RefreshTokenClaims | null> {
    const context = ((event.context ||= Object.create(null)).unauth ||=
      Object.create(null));

    if (context?.[refreshTokenName]) {
      return context[refreshTokenName];
    }

    const rt = getCookie(event, refreshTokenName);
    if (!rt) return null;

    const claims = await getProvider()
      .introspectRefreshToken(rt)
      .catch(() => null);
    if (!claims) return null;

    context[refreshTokenName] = claims;
    return claims;
  }

  async function authorize(
    event: H3Event,
    cb: (
      input: Omit<NormalizedAuthorizeInput, "subject" | "redirect_uri"> & {
        redirect_uri?: string;
      },
      validateRedirectUri: (
        redirectUri: string | undefined,
        registeredUris: string | string[],
      ) => string,
    ) => MaybePromise<{
      subject: string;
      redirect_uri: string;
      extraClaims?: Record<string, unknown>;
    }>,
  ) {
    const req = getQuery<AuthorizeRequest>(event);

    const validation = getProvider().validateAuthorizeRequest(req);
    if (!validation.success) {
      await oauthHooks.callHookParallel("authorizeFailed", validation, event);

      throw createError({
        status: 400,
        statusText: "Invalid request",
        cause: new Error(
          `${validation.error.error}: ${validation.error.error_description}`,
        ),
      });
    }
    const normalized = validation.value;

    const { subject, redirect_uri, extraClaims } = await cb(
      normalized,
      validateRedirectUri,
    );
    if (!redirect_uri) {
      await oauthHooks.callHookParallel(
        "authorizeFailed",
        {
          success: false,
          error: {
            error: "invalid_request",
            error_description: "The redirect_uri must be provided",
          },
        },
        event,
      );

      throw createError({
        status: 400,
        statusText: "Missing redirect_uri",
        cause: new Error("The redirect_uri must be provided"),
      });
    }

    await oauthHooks.callHookParallel(
      "authorizeRequest",
      {
        ...normalized,
        redirect_uri,
        subject,
      },
      event,
    );

    const redirect = await getProvider().issueAuthorizationCode({
      ...normalized,
      subject,
      redirect_uri,
      acExtraClaims: extraClaims,
    });

    if (!redirect.success) {
      await oauthHooks.callHookParallel("authorizeFailed", redirect, event);

      throw createError({
        status: 400,
        statusText: "Invalid request",
        cause: new Error(
          `${redirect.error.error}: ${redirect.error.error_description}`,
        ),
      });
    }

    await oauthHooks.callHookParallel("authorizeIssued", redirect, event);

    return new Response(null, {
      status: 302,
      headers: { Location: redirect.value },
    });
  }

  async function token(
    event: H3Event,
    cb?: (input: NormalizedTokenInput) => MaybePromise<{
      accessTokenExtraClaims?: Record<string, unknown>;
      refreshTokenExtraClaims?: Record<string, unknown>;
    }>,
  ) {
    const req = await readBody<TokenRequest>(event).catch(() => undefined);
    if (!req) {
      throw createError({
        status: 400,
        statusText: "Invalid or missing request body",
      });
    }

    const validation = getProvider().validateTokenRequest(req);
    if (!validation.success) {
      await oauthHooks.callHookParallel("tokenFailed", validation, event);

      throw createError({
        status: 400,
        statusText: "Invalid request",
        cause: new Error(
          `${validation.error.error}: ${validation.error.error_description}`,
        ),
      });
    }
    const normalized = validation.value;

    await oauthHooks.callHookParallel("tokenRequest", normalized, event);

    const { accessTokenExtraClaims, refreshTokenExtraClaims } =
      (await cb?.(normalized)) ?? {};

    const tokenGrant = await getProvider().issueTokenGrant(
      {
        ...normalized,
        accessTokenExtraClaims,
        refreshTokenExtraClaims,
      },
      {
        async introspectAuthorizationCode() {
          return (await getAuthorizationCode(event)) || undefined;
        },
        async introspectRefreshToken() {
          return (await getRefreshToken(event)) || undefined;
        },
      },
    );

    if (!tokenGrant.success) {
      await oauthHooks.callHookParallel("tokenFailed", tokenGrant, event);

      throw createError({
        status: 400,
        statusText: tokenGrant.error.error,
        cause: new Error(
          `${tokenGrant.error.error}: ${tokenGrant.error.error_description}`,
        ),
      });
    }

    const context = ((event.context ||= Object.create(null)).unauth ||=
      Object.create(null));
    if (tokenGrant.artifacts?.accessTokenClaims) {
      Object.assign(context, {
        [accessTokenName]: tokenGrant.artifacts.accessTokenClaims,
      });
    }
    if (
      tokenGrant.artifacts &&
      "refreshTokenClaims" in tokenGrant.artifacts &&
      tokenGrant.artifacts?.refreshTokenClaims
    ) {
      Object.assign(context, {
        [refreshTokenName]: tokenGrant.artifacts.refreshTokenClaims,
      });
    }

    await oauthHooks.callHookParallel("tokenIssued", tokenGrant, event);

    const { refresh_token, ...grant } = tokenGrant.value;
    if (refresh_token) {
      setCookie(event, refreshTokenName, refresh_token, {
        ...defaults?.refreshTokenCookieOptions,
        httpOnly: defaults?.refreshTokenCookieOptions?.httpOnly ?? true,
        sameSite: defaults?.refreshTokenCookieOptions?.sameSite ?? "lax",
        maxAge:
          defaults?.refreshTokenCookieOptions?.maxAge ??
          computeExpiresInSeconds(
            getProvider().refreshTokenOptions.encryptOptions.expiresIn,
          ),
      });
    }
    if (grant.access_token) {
      setCookie(event, accessTokenName, grant.access_token, {
        ...defaults?.accessTokenCookieOptions,
        sameSite: defaults?.accessTokenCookieOptions?.sameSite ?? "lax",
        maxAge: defaults?.accessTokenCookieOptions?.maxAge ?? grant.expires_in,
      });
    }

    return grant;
  }

  return {
    discovery: (options?: Omit<BuildOAuthDiscoveryArgs, "issuer">) => {
      // TODO: fix `getProvider().discovery` causing `this.issuer` to be undefined
      return buildOAuthDiscoveryDocument({
        ...options,
        issuer: getProvider().issuer,
      });
    },
    jwkSet: getProvider().jwkSet,
    getAuthorizationCode,
    getAccessToken,
    getRefreshToken,
    authorize,
    token,
  };
}

export function validateRedirectUri(
  redirectUri: string | undefined,
  registeredUris: string | string[],
): string {
  const validated = _coreValidateRedirectUri(redirectUri, registeredUris);

  if (!validated.success) {
    throw createError({
      status: 400,
      statusText: "Invalid redirect_uri",
      cause: new Error(
        `${validated.error.error}: ${validated.error.error_description}`,
      ),
    });
  }

  return validated.value;
}
