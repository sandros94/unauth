import type { SessionJWS, SessionJWE } from "unjwt/adapters/h3v1";
import { getJWSSession, getJWESession } from "unjwt/adapters/h3v1";
import { computeExpiresInSeconds } from "unjwt/utils";
import type { CookieSerializeOptions } from "cookie-esv1";
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
  type OAuthProviderOptions,
  type AccessTokenClaims,
  type RefreshTokenClaims,
  type AuthorizeRequest,
  type AuthorizeErrorResponse,
  type TokenRequest,
  type NormalizedAuthorizeInput,
  type IssueAuthorizationCodeReturn,
  type NormalizedTokenInput,
  type IssueAuthorizationCodeGrantReturn,
  type IssueClientCredentialsGrantReturn,
  type IssueRefreshTokenGrantReturn,
  type BuildOAuthDiscoveryArgs,
  OAuthProvider,
} from "../../core/oauth";
export { validateRedirectUri } from "../../core/oauth";

export type IssueTokenGrantReturn =
  | IssueAuthorizationCodeGrantReturn
  | IssueClientCredentialsGrantReturn
  | IssueRefreshTokenGrantReturn;

export interface H3OAuthProviderOptions extends OAuthProviderOptions {
  defaults?: {
    accessTokenName?: string;
    accessTokenCookieOptions?: CookieSerializeOptions;
    refreshTokenName?: string;
    refreshTokenCookieOptions?: CookieSerializeOptions;
  };
}

export type OAuthAuthorizeCallback = (
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

export type OAuthTokenCallback = (input: NormalizedTokenInput) => MaybePromise<{
  accessTokenExtraClaims?: Record<string, unknown>;
  refreshTokenExtraClaims?: Record<string, unknown>;
}>;

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
export function useOAuthProvider(options: H3OAuthProviderOptions) {
  const { defaults, ...opts } = options;
  const {
    accessTokenName = DEFAULT_AT_NAME,
    refreshTokenName = DEFAULT_RT_NAME,
  } = defaults || {};
  function getProvider() {
    if (!_oauthProvider) {
      console.log("Creating new OAuthProvider");
      _oauthProvider = new OAuthProvider(opts);
      console.log("issuer:", _oauthProvider.issuer);
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
          .catch(() => undefined)
      : undefined;
  }
  async function getRefreshToken(
    event: H3Event,
  ): Promise<RefreshTokenClaims | undefined> {
    const { encryptOptions, decryptOptions, privateKey } =
      getProvider().refreshTokenOptions;

    const session = await getJWESession<RefreshTokenClaims>(event, {
      name: refreshTokenName,
      key: privateKey,
      maxAge: encryptOptions.expiresIn,
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
      exp: Math.floor(expiresAt / 1000),
    } as RefreshTokenClaims;
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
      maxAge: signOptions.expiresIn,
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
      exp: Math.floor(expiresAt / 1000),
    } as AccessTokenClaims;
  }

  async function authorize(event: H3Event, cb: OAuthAuthorizeCallback) {
    const req = getQuery<AuthorizeRequest>(event);

    const validation = getProvider().validateAuthorizeRequest(req);
    if (!validation.success) {
      await oauthHooks.callHookParallel("authorizeFailed", validation, event);

      setResponseStatus(event, 400, validation.error.error);
      return validation.error;
    }
    const normalized = validation.value;

    let cbReturn =
      (cb as OAuthAuthorizeCallback | undefined)?.(normalized) || undefined;
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
      await oauthHooks.callHookParallel(
        "authorizeFailed",
        { success: false, error },
        event,
      );

      setResponseStatus(event, 400, error.error);
      return error;
    }

    const { subject, redirect_uri, extraClaims } = cbReturn;

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

      setResponseStatus(event, 400, redirect.error.error);
      return redirect.error;
    }

    await oauthHooks.callHookParallel("authorizeIssued", redirect, event);

    return new Response(null, {
      status: 302,
      headers: { Location: redirect.value },
    });
  }

  async function token(event: H3Event, cb?: OAuthTokenCallback) {
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
      await oauthHooks.callHookParallel("tokenFailed", validation, event);

      setResponseStatus(event, 400, validation.error.error);
      return validation.error;
    }
    const normalized = validation.value;

    await oauthHooks.callHookParallel("tokenRequest", normalized, event);

    const { accessTokenExtraClaims, refreshTokenExtraClaims } =
      (await cb?.(normalized)) ?? {};

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
      await oauthHooks.callHookParallel("tokenFailed", tokenGrant, event);

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
    discoveryDocument: getProvider().discoveryDocument,
    jwkSet: getProvider().jwkSet,
    getAuthorizationCode,
    getAccessToken,
    getRefreshToken,
    authorize,
    token,
  };
}

export function createOAuthRouter(
  options: H3OAuthProviderOptions & {
    preemptive?: boolean;
    discovery?: BuildOAuthDiscoveryArgs;
    authorize: OAuthAuthorizeCallback;
    token?: OAuthTokenCallback;
  },
): Router {
  const { preemptive, authorize, token, ...opts } = options;
  const provider = useOAuthProvider(opts);
  const discoveryDoc = provider.discoveryDocument;

  const oauthRouter = createRouter({ preemptive })
    // OAuth Provider Configuration (Discovery)
    .get(
      "/.well-known/oauth-configuration",
      defineEventHandler(() => {
        return discoveryDoc;
      }),
    )
    // JWKS (public keys)
    .get(
      discoveryDoc.jwks_uri.slice(discoveryDoc.issuer.length),
      defineEventHandler(() => provider.jwkSet),
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
    );

  return oauthRouter;
}
