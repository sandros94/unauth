import { computeExpiresInSeconds } from "unjwt/utils";
import type { CookieSerializeOptions } from "cookie-es";
import { createHooks } from "hookable";
import {
  type H3Event,
  type Router,
  type EventHandler,
  setResponseStatus,
  getQuery,
  readBody,
  getCookie,
  setCookie,
  useBase,
  createRouter,
  defineEventHandler,
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
  buildOIDCDiscoveryDocument,
} from "../../core/oidc";
export { validateRedirectUri } from "../../core/oidc";

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

export type AuthorizeCallback = (
  input: Omit<NormalizedAuthorizeInput, "subject" | "redirect_uri"> & {
    redirect_uri?: string;
  },
) => MaybePromise<{
  subject: string;
  redirect_uri: string;
  extraClaims?: Record<string, unknown>;
}>;

export type TokenCallback = (input: NormalizedTokenInput) => MaybePromise<{
  accessTokenExtraClaims?: Record<string, unknown>;
  refreshTokenExtraClaims?: Record<string, unknown>;
  idTokenExtraClaims?: Record<string, unknown>;
}>;

export type UserInfoCallback = (args: {
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
          .catch(() => undefined)
      : undefined;
  }
  async function getAccessToken(
    event: H3Event,
  ): Promise<AccessTokenClaims | undefined> {
    const context = ((event.context ||= Object.create(null)).unauth ||=
      Object.create(null));

    if (context?.[accessTokenName]) {
      return context[accessTokenName];
    }

    const at =
      event.headers.get("Authorization")?.split(" ")?.[1] ||
      getCookie(event, accessTokenName);
    if (!at) return undefined;

    const claims = await getProvider()
      .introspectAccessToken(at)
      .catch(() => null);
    if (!claims) return undefined;

    context[accessTokenName] = claims;
    return claims;
  }
  async function getRefreshToken(
    event: H3Event,
  ): Promise<RefreshTokenClaims | undefined> {
    const context = ((event.context ||= Object.create(null)).unauth ||=
      Object.create(null));

    if (context?.[refreshTokenName]) {
      return context[refreshTokenName];
    }

    const rt = getCookie(event, refreshTokenName);
    if (!rt) return undefined;

    const claims = await getProvider()
      .introspectRefreshToken(rt)
      .catch(() => null);
    if (!claims) return undefined;

    context[refreshTokenName] = claims;
    return claims;
  }
  async function getIdToken(
    event: H3Event,
  ): Promise<IdTokenClaims | undefined> {
    const context = ((event.context ||= Object.create(null)).unauth ||=
      Object.create(null));

    if (context?.[idTokenName]) {
      return context[idTokenName];
    }

    const rt = getCookie(event, idTokenName);
    if (!rt) return undefined;

    const claims = await getProvider()
      .introspectIdToken(rt)
      .catch(() => null);
    if (!claims) return undefined;

    context[idTokenName] = claims;
    return claims;
  }

  async function authorize(event: H3Event, cb: AuthorizeCallback) {
    const req = getQuery<AuthorizeRequest>(event);

    const validation = getProvider().validateAuthorizeRequest(req);
    if (!validation.success) {
      await oidcHooks.callHookParallel("authorizeFailed", validation, event);

      setResponseStatus(event, 400, validation.error.error);
      return validation.error;
    }
    const normalized = validation.value;

    let cbReturn =
      (cb as AuthorizeCallback | undefined)?.(normalized) || undefined;
    if (cbReturn instanceof Promise) {
      cbReturn = await cbReturn.catch(() => undefined);
    }
    if (!cbReturn || !cbReturn.subject || !cbReturn.redirect_uri) {
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

  async function token(event: H3Event, cb?: TokenCallback) {
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

      setResponseStatus(event, 400, tokenGrant.error.error);
      return tokenGrant.error;
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

  async function userinfo(event: H3Event, cb?: UserInfoCallback) {
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
      sub: accessToken.sub,
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

export function createOAuthRouter(
  base: string,
  options: H3OIDCProviderOptions & {
    preemptive?: boolean;
    discovery?: Omit<BuildOIDCDiscoveryArgs, "prefix">;
    authorize: AuthorizeCallback;
    token?: TokenCallback;
    userinfo?: UserInfoCallback;
  },
): EventHandler;
export function createOAuthRouter(
  options: H3OIDCProviderOptions & {
    preemptive?: boolean;
    discovery?: BuildOIDCDiscoveryArgs;
    authorize: AuthorizeCallback;
    token?: TokenCallback;
    userinfo?: UserInfoCallback;
  },
): Router;
export function createOAuthRouter(...args: any[]): EventHandler | Router {
  const [base, options] = (args.length === 1 ? [undefined, args[0]] : args) as [
    string | undefined,
    H3OIDCProviderOptions & {
      preemptive?: boolean;
      discovery?: BuildOIDCDiscoveryArgs;
      authorize: AuthorizeCallback;
      token?: TokenCallback;
      userinfo?: UserInfoCallback;
    },
  ];

  const { preemptive, discovery, authorize, token, userinfo, ...opts } =
    options;
  const oidcRouter = createRouter({ preemptive });
  const provider = useOIDCProvider(opts);

  const rmBase = sliceBaseUrl(opts.issuer, discovery?.prefix);
  const discoveryDoc = provider.discovery(
    base === undefined
      ? discovery
      : {
          ...discovery,
          prefix: base,
        },
  );

  // OIDC Provider Configuration (Discovery)
  oidcRouter.get(
    "/.well-known/openid-configuration",
    defineEventHandler(() => {
      return discoveryDoc;
    }),
  );

  // JWKS (public keys)
  oidcRouter.get(
    rmBase(discoveryDoc.jwks_uri),
    defineEventHandler(() => provider.jwkSet),
  );

  // Authorization Endpoint
  oidcRouter.get(
    rmBase(discoveryDoc.authorization_endpoint),
    defineEventHandler(async (event) => {
      return provider.authorize(event, authorize);
    }),
  );

  // Token Endpoint
  oidcRouter.post(
    rmBase(discoveryDoc.token_endpoint),
    defineEventHandler(async (event) => {
      return provider.token(event, token);
    }),
  );

  // UserInfo Endpoint
  oidcRouter.get(
    rmBase(discoveryDoc.userinfo_endpoint),
    defineEventHandler(async (event) => {
      return provider.userinfo(event, userinfo);
    }),
  );

  return base === undefined ? oidcRouter : useBase(base, oidcRouter.handler);
}

function sliceBaseUrl(issuer: string, prefix?: string) {
  const baseUrl = `${issuer.replace(/\/+$/, "")}${
    prefix ? `/${prefix.replace(/^\/+|\/+$/g, "")}` : ""
  }`;

  return (input: string) => input.slice(baseUrl.length);
}
