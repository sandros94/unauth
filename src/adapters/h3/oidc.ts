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
  type OIDCProviderOptions,
  type AccessTokenClaims,
  type RefreshTokenClaims,
  type IdTokenClaims,
  type AuthorizeRequest,
  type TokenRequest,
  type NormalizedAuthorizeInput,
  type IssueAuthorizationCodeReturn,
  type NormalizedTokenInput,
  type IssueTokenGrantReturn,
  type BuildOIDCDiscoveryArgs,
  type OIDCUserInfoProfile,
  OIDCProvider,
  validateRedirectUri as _coreValidateRedirectUri,
  buildOIDCDiscoveryDocument,
} from "../../core/oidc";

export interface OIDCHooks {
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

export const oidcHooks = createHooks<OIDCHooks>();

const DEFAULT_AT_NAME = "access_token";
const DEFAULT_RT_NAME = "refresh_token";
const DEFAULT_IT_NAME = "id_token";

let _oidcProvider: OIDCProvider | null = null;
export function useOIDCProvider(
  options: OIDCProviderOptions & {
    defaults?: {
      accessTokenName?: string;
      accessTokenCookieOptions?: CookieSerializeOptions;
      refreshTokenName?: string;
      refreshTokenCookieOptions?: CookieSerializeOptions;
      idTokenName?: string;
      idTokenCookieOptions?: CookieSerializeOptions;
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
  async function getIdToken(event: H3Event): Promise<IdTokenClaims | null> {
    const context = ((event.context ||= Object.create(null)).unauth ||=
      Object.create(null));

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
      await oidcHooks.callHookParallel("authorizeFailed", validation, event);

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
      await oidcHooks.callHookParallel(
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

    await oidcHooks.callHookParallel(
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
      await oidcHooks.callHookParallel("authorizeFailed", redirect, event);

      throw createError({
        status: 400,
        statusText: "Invalid request",
        cause: new Error(
          `${redirect.error.error}: ${redirect.error.error_description}`,
        ),
      });
    }

    await oidcHooks.callHookParallel("authorizeIssued", redirect, event);

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
      await oidcHooks.callHookParallel("tokenFailed", validation, event);

      throw createError({
        status: 400,
        statusText: "Invalid request",
        cause: new Error(
          `${validation.error.error}: ${validation.error.error_description}`,
        ),
      });
    }
    const normalized = validation.value;

    await oidcHooks.callHookParallel("tokenRequest", normalized, event);

    const {
      accessTokenExtraClaims,
      refreshTokenExtraClaims,
      idTokenExtraClaims,
    } = (await cb?.(normalized)) ?? {};

    const tokenGrant = await getProvider().issueTokenGrant(
      {
        ...normalized,
        accessTokenExtraClaims,
        refreshTokenExtraClaims,
        idTokenExtraClaims,
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
      await oidcHooks.callHookParallel("tokenFailed", tokenGrant, event);

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
    if (tokenGrant.artifacts?.accessTokenClaims !== undefined) {
      Object.assign(context, {
        [accessTokenName]: tokenGrant.artifacts.accessTokenClaims,
      });
    }
    if (
      tokenGrant.artifacts &&
      "refreshTokenClaims" in tokenGrant.artifacts &&
      tokenGrant.artifacts?.refreshTokenClaims !== undefined
    ) {
      Object.assign(context, {
        [refreshTokenName]: tokenGrant.artifacts.refreshTokenClaims,
      });
    }
    if (
      tokenGrant.artifacts &&
      "idTokenClaims" in tokenGrant.artifacts &&
      tokenGrant.artifacts?.idTokenClaims !== undefined
    ) {
      Object.assign(context, {
        [idTokenName]: tokenGrant.artifacts.idTokenClaims,
      });
    }

    await oidcHooks.callHookParallel("tokenIssued", tokenGrant, event);

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
    if ("id_token" in grant && grant.id_token) {
      setCookie(event, idTokenName, grant.id_token, {
        ...defaults?.idTokenCookieOptions,
        sameSite: defaults?.idTokenCookieOptions?.sameSite ?? "lax",
        maxAge:
          defaults?.idTokenCookieOptions?.maxAge ??
          computeExpiresInSeconds(
            getProvider().idTokenOptions.signOptions.expiresIn,
          ),
      });
    }

    return grant;
  }

  async function userInfo(
    event: H3Event,
    cb?: (at: AccessTokenClaims) => MaybePromise<OIDCUserInfoProfile>,
  ) {
    const at = await getAccessToken(event);
    if (!at) {
      throw createError({
        status: 401,
        statusText: "Unauthorized",
      });
    }

    const profile = await cb?.(at);

    return getProvider().buildUserInfo({
      sub: at.sub,
      ...profile,
    });
  }

  return {
    discovery: (options?: Omit<BuildOIDCDiscoveryArgs, "issuer">) => {
      // TODO: fix `getProvider().discovery` causing `this.issuer` to be undefined
      return buildOIDCDiscoveryDocument({
        ...options,
        issuer: getProvider().issuer,
      });
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
