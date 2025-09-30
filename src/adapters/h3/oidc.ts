import { type H3Event, getCookie, getQuery, readBody, createError } from "h3";

import type { MaybePromise } from "../../types";

import {
  type OIDCProviderOptions,
  type AccessTokenClaims,
  type RefreshTokenClaims,
  type IdTokenClaims,
  type AuthorizeRequest,
  type TokenRequest,
  type NormalizedAuthorizeInput,
  type NormalizedTokenInput,
  type IssueTokenReturn,
  type BuildOIDCDiscoveryArgs,
  OIDCProvider,
  validateRedirectUri as _coreValidateRedirectUri,
  buildOIDCDiscoveryDocument,
} from "../../core/oidc";

const DEFAULT_AT_NAME = "access_token";
const DEFAULT_RT_NAME = "refresh_token";
const DEFAULT_IT_NAME = "id_token";

let _oidcProvider: OIDCProvider | null = null;
export function useOIDCProvider(
  options: OIDCProviderOptions & {
    defaults?: {
      accessTokenName?: string;
      refreshTokenName?: string;
      idTokenName?: string;
    };
  },
) {
  const { defaults, ...opts } = options;
  const {
    accessTokenName = DEFAULT_AT_NAME,
    refreshTokenName = DEFAULT_RT_NAME,
    idTokenName = DEFAULT_IT_NAME,
  } = defaults || {};
  function getProvider() {
    if (!_oidcProvider) {
      console.log("Creating new OIDCProvider");
      console.log("issuer:", opts.issuer);
      _oidcProvider = new OIDCProvider(opts);
    }
    return _oidcProvider;
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
  async function getIdToken(event: H3Event): Promise<IdTokenClaims | null> {
    const context = (event.context ||= {}).auth ||= {};

    if (context?.[idTokenName]) {
      return context[idTokenName];
    }

    const rt = getCookie(event, idTokenName);
    if (!rt) return null;

    const claims = await getProvider()
      .introspectIdToken(rt)
      .catch(() => null);
    if (!claims) return null;

    context[idTokenName] = claims;
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
      idTokenExtraClaims?: Record<string, unknown>;
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

    const { accessTokenExtraClaims, refreshTokenExtraClaims, idTokenExtraClaims } =
      await cb?.(normalized) ?? {};

    let tokenGrant: IssueTokenReturn;
    switch (normalized.grant_type) {
      case "authorization_code": {
        tokenGrant = await getProvider().issueAuthorizationCodeGrant({
          ...normalized,
          accessTokenExtraClaims,
          refreshTokenExtraClaims,
          idTokenExtraClaims,
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
          idTokenExtraClaims,
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
    if (tokenGrant.artifacts?.accessTokenClaims !== undefined) {
      Object.assign(context, { [accessTokenName]: tokenGrant.artifacts.accessTokenClaims });
    }
    if (
      tokenGrant.artifacts &&
      "refreshTokenClaims" in tokenGrant.artifacts &&
      tokenGrant.artifacts?.refreshTokenClaims !== undefined
    ) {
      Object.assign(context, { [refreshTokenName]: tokenGrant.artifacts.refreshTokenClaims });
    }
    if (
      tokenGrant.artifacts &&
      "idTokenClaims" in tokenGrant.artifacts &&
      tokenGrant.artifacts?.idTokenClaims !== undefined
    ) {
      Object.assign(context, { [idTokenName]: tokenGrant.artifacts.idTokenClaims });
    }

    return tokenGrant.value;
  }

  async function userInfo(event: H3Event) {
    const at = await getAccessToken(event);
    if (!at) {
      throw createError({
        status: 401,
        statusText: "Unauthorized",
      });
    }

    return getProvider().buildUserInfo({
      sub: at.sub,
      // TODO: other standard claims
    });
  }

  return {
    discovery: (options?: Omit<BuildOIDCDiscoveryArgs, "issuer">) => {
      // TODO: fix `getProvider().discovery` causing `this.issuer` to be undefined
      return buildOIDCDiscoveryDocument({ ...options, issuer: getProvider().issuer })
    },
    userInfo,
    jwkSet: getProvider().jwkSet,
    getAuthorizationCode,
    getAccessToken,
    getRefreshToken,
    getIdToken,
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
