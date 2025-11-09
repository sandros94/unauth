import type { SessionJWS, SessionJWE } from "unjwt/adapters/h3v1";
import { getJWSSession, getJWESession } from "unjwt/adapters/h3v1";
import { computeExpiresInSeconds } from "unjwt/utils";
import type { CookieSerializeOptions } from "cookie-es";
import { createHooks } from "hookable";
import {
  type H3Event,
  type Router,
  setResponseStatus,
  getQuery,
  readBody,
  setCookie,
  createRouter,
  defineEventHandler,
} from "h3v1";

import type { MaybePromise } from "../../types";

import {
  type Failure,
  type OIDCProviderOptions,
  type AccessTokenClaims,
  type RefreshTokenClaims,
  type IdTokenClaims,
  type AuthorizeRequest,
  type AuthorizeErrorResponse,
  type TokenRequest,
  type NormalizedAuthorizeInput,
  type IssueAuthorizationCodeReturn,
  type NormalizedTokenInput,
  type IssueAuthorizationCodeGrantReturn,
  type IssueClientCredentialsGrantReturn,
  type IssueRefreshTokenGrantReturn,
  type BuildOIDCDiscoveryArgs,
  type OIDCUserInfoProfile,
  OIDCProvider,
} from "../../core/oidc";
export { validateRedirectUri } from "../../core/oidc";

export type IssueTokenGrantReturn =
  | IssueAuthorizationCodeGrantReturn
  | IssueClientCredentialsGrantReturn
  | IssueRefreshTokenGrantReturn;

export interface H3OIDCProviderOptions extends OIDCProviderOptions {
  defaults?: {
    accessTokenName?: string;
    accessTokenCookieOptions?: CookieSerializeOptions;
    refreshTokenName?: string;
    refreshTokenCookieOptions?: CookieSerializeOptions;
    idTokenName?: string;
    idTokenCookieOptions?: CookieSerializeOptions;
  };
}

export type OIDCAuthorizeCallback = (
  input: Omit<NormalizedAuthorizeInput, "subject" | "redirect_uri"> & {
    redirect_uri?: string;
  },
) => MaybePromise<
  | {
      subject: string;
      redirect_uri: string;
      extraClaims?: Record<string, unknown>;
    }
  | AuthorizeErrorResponse
>;

export type OIDCTokenCallback = (input: NormalizedTokenInput) => MaybePromise<{
  accessTokenExtraClaims?: Record<string, unknown>;
  refreshTokenExtraClaims?: Record<string, unknown>;
  idTokenExtraClaims?: Record<string, unknown>;
}>;

export type OIDCUserInfoCallback = (args: {
  accessToken: AccessTokenClaims;
  idToken?: IdTokenClaims;
}) => MaybePromise<OIDCUserInfoProfile>;

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
export function useOIDCProvider(options: H3OIDCProviderOptions) {
  const { defaults, ...opts } = options;
  const {
    accessTokenName = DEFAULT_AT_NAME,
    refreshTokenName = DEFAULT_RT_NAME,
    idTokenName = DEFAULT_IT_NAME,
  } = defaults || {};
  function getProvider() {
    if (!_oidcProvider) {
      console.log("Creating new OIDCProvider");
      _oidcProvider = new OIDCProvider(opts);
      console.log("issuer:", _oidcProvider.issuer);
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
          .catch(() => undefined)
      : undefined;
  }
  async function getAccessToken(
    event: H3Event,
  ): Promise<AccessTokenClaims | undefined> {
    const { signOptions, verifyOptions, ...key } =
      getProvider().accessTokenOptions;

    const session = await getJWSSession<AccessTokenClaims>(event, {
      name: accessTokenName,
      sessionHeader: "Authorization",
      key,
      jws: {
        signOptions,
        verifyOptions,
      },
    }).catch(() => null);

    if (!session) return undefined;

    const { id, createdAt, expiresAt, data } = session;
    return {
      ...data,
      jti: id,
      iat: Math.floor(createdAt / 1000),
      exp: Math.floor(expiresAt! / 1000),
    } as AccessTokenClaims;
  }
  async function getRefreshToken(
    event: H3Event,
  ): Promise<RefreshTokenClaims | undefined> {
    const { encryptOptions, decryptOptions, privateKey } =
      getProvider().refreshTokenOptions;

    const session = await getJWESession<RefreshTokenClaims>(event, {
      name: refreshTokenName,
      key: privateKey,
      jwe: {
        encryptOptions,
        decryptOptions,
      },
    }).catch(() => null);

    if (!session) return undefined;

    const { id, createdAt, expiresAt, data } = session;
    return {
      ...data,
      jti: id,
      iat: Math.floor(createdAt / 1000),
      exp: Math.floor(expiresAt! / 1000),
    } as RefreshTokenClaims;
  }
  async function getIdToken(
    event: H3Event,
  ): Promise<IdTokenClaims | undefined> {
    const { signOptions, verifyOptions, ...key } = getProvider().idTokenOptions;

    const session = await getJWSSession<IdTokenClaims>(event, {
      name: idTokenName,
      key,
      jws: {
        signOptions,
        verifyOptions,
      },
    }).catch(() => null);

    if (!session) return undefined;

    const { id, createdAt, expiresAt, data } = session;
    return {
      ...data,
      jti: id,
      iat: Math.floor(createdAt / 1000),
      exp: Math.floor(expiresAt! / 1000),
    } as IdTokenClaims;
  }

  async function authorize(event: H3Event, cb: OIDCAuthorizeCallback) {
    const req = getQuery<AuthorizeRequest>(event);

    const validation = getProvider().validateAuthorizeRequest(req);
    if (!validation.success) {
      await oidcHooks.callHookParallel("authorizeFailed", validation, event);

      setResponseStatus(event, 400, validation.error.error);
      return validation.error;
    }
    const normalized = validation.value;

    let cbReturn =
      (cb as OIDCAuthorizeCallback | undefined)?.(normalized) || undefined;
    if (cbReturn instanceof Promise) {
      cbReturn = await cbReturn.catch(() => undefined);
    }
    if (
      !cbReturn ||
      "error" in cbReturn ||
      !cbReturn.subject ||
      !cbReturn.redirect_uri
    ) {
      const error = {
        error: "server_error",
        error_description:
          "Server implementation error: missing return values for authorize endpoint",
      } as const;
      await oidcHooks.callHookParallel(
        "authorizeFailed",
        { success: false, error },
        event,
      );

      setResponseStatus(event, 400, error.error);
      return error;
    }

    const { subject, redirect_uri, extraClaims } = cbReturn;

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

      setResponseStatus(event, 400, redirect.error.error);
      return redirect.error;
    }

    await oidcHooks.callHookParallel("authorizeIssued", redirect, event);

    return new Response(null, {
      status: 302,
      headers: { Location: redirect.value },
    });
  }

  async function token(event: H3Event, cb?: OIDCTokenCallback) {
    const req = await readBody<TokenRequest>(event).catch(() => undefined);
    if (!req) {
      setResponseStatus(event, 400, "Invalid or missing request body");
      return {
        error: "invalid_request",
        error_description: "Invalid or missing request body",
      };
    }

    const validation = getProvider().validateTokenRequest(req);
    if (!validation.success) {
      await oidcHooks.callHookParallel("tokenFailed", validation, event);

      setResponseStatus(event, 400, validation.error.error);
      return validation.error;
    }
    const normalized = validation.value;

    await oidcHooks.callHookParallel("tokenRequest", normalized, event);

    const {
      accessTokenExtraClaims,
      refreshTokenExtraClaims,
      idTokenExtraClaims,
    } = (await cb?.(normalized)) ?? {};

    let tokenGrant: IssueTokenGrantReturn;

    switch (normalized.grant_type) {
      case "authorization_code": {
        const code = await getAuthorizationCode(event);
        if (!code) {
          setResponseStatus(event, 400, "invalid_grant");
          return {
            error: "invalid_grant",
            error_description: "Invalid authorization code",
          };
        }
        tokenGrant = await getProvider().issueAuthorizationCodeGrant(
          {
            ...normalized,
            code,
            accessTokenExtraClaims,
            refreshTokenExtraClaims,
            idTokenExtraClaims,
          },
          {},
        );
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
        const refresh_token = await getRefreshToken(event);
        if (!refresh_token) {
          setResponseStatus(event, 400, "invalid_grant");
          return {
            error: "invalid_grant",
            error_description: "Invalid refresh token",
          };
        }
        tokenGrant = await getProvider().issueRefreshTokenGrant(
          {
            ...normalized,
            refresh_token,
            accessTokenExtraClaims,
            refreshTokenExtraClaims,
            idTokenExtraClaims,
          },
          {},
        );
        break;
      }
      default: {
        setResponseStatus(event, 400, "unsupported_grant_type");
        return {
          error: "unsupported_grant_type",
          error_description: `Unsupported grant_type: ${(normalized as any).grant_type}`,
        };
      }
    }

    if (!tokenGrant.success) {
      await oidcHooks.callHookParallel("tokenFailed", tokenGrant, event);

      setResponseStatus(event, 400, tokenGrant.error.error);
      return tokenGrant.error;
    }

    // If successful, update event's context with tokens' claims
    if (tokenGrant.artifacts) {
      if (!event.context.sessions) {
        event.context.sessions = Object.create(null);
      }

      if (tokenGrant.artifacts?.accessTokenClaims) {
        const { jti, iat, exp, ...data } =
          tokenGrant.artifacts.accessTokenClaims;
        event.context.sessions![accessTokenName] = {
          id: jti,
          createdAt: iat * 1000,
          expiresAt: exp * 1000,
          data,
        } as SessionJWS<AccessTokenClaims>;
      }

      if (
        "refreshTokenClaims" in tokenGrant.artifacts &&
        tokenGrant.artifacts?.refreshTokenClaims
      ) {
        const { jti, iat, exp, ...data } =
          tokenGrant.artifacts.refreshTokenClaims;
        event.context.sessions![refreshTokenName] = {
          id: jti,
          createdAt: iat * 1000,
          expiresAt: exp * 1000,
          data,
        } as SessionJWE<RefreshTokenClaims>;
      }

      if (
        "idTokenClaims" in tokenGrant.artifacts &&
        tokenGrant.artifacts?.idTokenClaims
      ) {
        const { jti, iat, exp, ...data } = tokenGrant.artifacts.idTokenClaims;
        event.context.sessions![idTokenName] = {
          id: jti,
          createdAt: iat * 1000,
          expiresAt: exp * 1000,
          data,
        } as SessionJWS<IdTokenClaims>;
      }
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

  async function userinfo(event: H3Event, cb?: OIDCUserInfoCallback) {
    const [accessToken, idToken] = await Promise.all([
      getAccessToken(event),
      getIdToken(event),
    ]);
    if (!accessToken) {
      setResponseStatus(event, 401, "Unauthorized");
      return {
        error: "invalid_token",
        error_description: "Access token is missing or invalid",
      };
    }

    const profile = await cb?.({
      accessToken,
      idToken,
    });

    return getProvider().buildUserInfo({
      ...idToken,
      aud: accessToken.aud,
      ...profile,
      sub: accessToken.sub,
    });
  }

  return {
    discoveryDocument: getProvider().discoveryDocument,
    userinfo,
    jwkSet: getProvider().jwkSet,
    getAuthorizationCode,
    getAccessToken,
    getRefreshToken,
    getIdToken,
    authorize,
    token,
  };
}

export function createOIDCRouter(
  options: H3OIDCProviderOptions & {
    preemptive?: boolean;
    discovery?: BuildOIDCDiscoveryArgs;
    authorize: OIDCAuthorizeCallback;
    token?: OIDCTokenCallback;
    userinfo?: OIDCUserInfoCallback;
  },
): Router {
  const { preemptive, authorize, token, userinfo, ...opts } = options;
  const provider = useOIDCProvider(opts);
  const discoveryDoc = provider.discoveryDocument;

  const oidcRouter = createRouter({ preemptive })
    // JWKS (public keys)
    .get(
      discoveryDoc.jwks_uri.slice(discoveryDoc.issuer.length),
      defineEventHandler(() => provider.jwkSet),
    )
    // OIDC Provider Configuration (Discovery)
    .get(
      "/.well-known/openid-configuration",
      defineEventHandler(() => {
        return discoveryDoc;
      }),
    )
    // Authorization Endpoint
    .get(
      discoveryDoc.authorization_endpoint.slice(discoveryDoc.issuer.length),
      defineEventHandler(async (event) => {
        return provider.authorize(event, authorize);
      }),
    )
    // Token Endpoint
    .post(
      discoveryDoc.token_endpoint.slice(discoveryDoc.issuer.length),
      defineEventHandler(async (event) => {
        return provider.token(event, token);
      }),
    )
    // UserInfo Endpoint
    .get(
      discoveryDoc.userinfo_endpoint.slice(discoveryDoc.issuer.length),
      defineEventHandler(async (event) => {
        return provider.userinfo(event, userinfo);
      }),
    );

  return oidcRouter;
}
