import { type H3Event, getCookie, getQuery, readBody, createError } from "h3";

import type { MaybePromise } from "../../types";

import {
  type OAuthProviderOptions,
  type AccessTokenClaims,
  type RefreshTokenClaims,
  type AuthorizeRequest,
  type TokenRequest,
  type NormalizedAuthorizeInput,
  type NormalizedTokenInput,
  type IssueTokenReturn,
  OAuthProvider,
  validateRedirectUri as _coreValidateRedirectUri,
} from "../../core/oauth";

const DEFAULT_AT_NAME = "access_token";
const DEFAULT_RT_NAME = "refresh_token";

let _oauthProvider: OAuthProvider | null = null;
export function useOAuthProvider(
  options: OAuthProviderOptions & {
    defaults?: {
      accessTokenName?: string;
      refreshTokenName?: string;
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
    return req && "grant_type" in req && req.grant_type === "authorization_code"
      ? getProvider()
          .issueAuthorizationCodeGrant(req)
          .catch(() => null)
      : null;
  }
  async function getAccessToken(
    event: H3Event,
  ): Promise<AccessTokenClaims | null> {
    const context = (event.context ||= {}).auth ||= {};

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
    const context = (event.context ||= {}).auth ||= {};

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
      throw createError({
        status: 400,
        statusText: "Missing redirect_uri",
        cause: new Error("The redirect_uri must be provided"),
      });
    }

    const redirect = await getProvider().issueAuthorizationCode({
      ...normalized,
      subject,
      redirect_uri,
      acExtraClaims: extraClaims,
    });

    if (!redirect.success) {
      throw createError({
        status: 400,
        statusText: "Invalid request",
        cause: new Error(
          `${redirect.error.error}: ${redirect.error.error_description}`,
        ),
      });
    }

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
      throw createError({
        status: 400,
        statusText: "Invalid request",
        cause: new Error(
          `${validation.error.error}: ${validation.error.error_description}`,
        ),
      });
    }
    const normalized = validation.value;

    const { accessTokenExtraClaims, refreshTokenExtraClaims } =
      await cb?.(normalized) ?? {};

    let tokenGrant: IssueTokenReturn;
    switch (normalized.grant_type) {
      case "authorization_code": {
        tokenGrant = await getProvider().issueAuthorizationCodeGrant({
          ...normalized,
          accessTokenExtraClaims,
          refreshTokenExtraClaims,
        });
        break;
      }
      case "client_credentials": {
        tokenGrant = await getProvider().issueClientCredentialsGrant({
          ...normalized,
          accessTokenExtraClaims,
        });
        break;
      }
      case "refresh_token": {
        tokenGrant = await getProvider().issueRefreshTokenGrant({
          ...normalized,
          accessTokenExtraClaims,
          refreshTokenExtraClaims,
        });
        break;
      }
      default: {
        throw createError({
          status: 400,
          statusText: "Invalid grant type",
        });
      }
    }

    if (!tokenGrant.success) {
      throw createError({
        status: 400,
        statusText: tokenGrant.error.error,
        cause: new Error(
          `${tokenGrant.error.error}: ${tokenGrant.error.error_description}`,
        ),
      });
    }

    const context = (event.context ||= {}).auth ||= {};
    if (tokenGrant.artifacts?.accessTokenClaims) {
      Object.assign(context, { [accessTokenName]: tokenGrant.artifacts.accessTokenClaims });
    }
    if (
      tokenGrant.artifacts &&
      "refreshTokenClaims" in tokenGrant.artifacts &&
      tokenGrant.artifacts?.refreshTokenClaims
    ) {
      Object.assign(context, { [refreshTokenName]: tokenGrant.artifacts.refreshTokenClaims });
    }

    return tokenGrant.value;
  }

  return {
    discovery: getProvider().discovery,
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
