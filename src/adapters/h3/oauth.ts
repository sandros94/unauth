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
  buildOAuthDiscoveryDocument,
} from "../../core/oauth";
export { validateRedirectUri } from "../../core/oauth";

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
) => MaybePromise<{
  subject: string;
  redirect_uri: string;
  extraClaims?: Record<string, unknown>;
}>;

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
    if (!cbReturn || !cbReturn.subject || !cbReturn.redirect_uri) {
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

      setResponseStatus(event, 400, tokenGrant.error.error);
      return tokenGrant.error;
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

export function createOAuthRouter(
  base: string,
  options: H3OAuthProviderOptions & {
    preemptive?: boolean;
    discovery?: Omit<BuildOAuthDiscoveryArgs, "prefix">;
    authorize: OAuthAuthorizeCallback;
    token?: OAuthTokenCallback;
  },
): EventHandler;
export function createOAuthRouter(
  options: H3OAuthProviderOptions & {
    preemptive?: boolean;
    discovery?: BuildOAuthDiscoveryArgs;
    authorize: OAuthAuthorizeCallback;
    token?: OAuthTokenCallback;
  },
): Router;
export function createOAuthRouter(...args: any[]): EventHandler | Router {
  const [base, options] = (args.length === 1 ? [undefined, args[0]] : args) as [
    string | undefined,
    H3OAuthProviderOptions & {
      preemptive?: boolean;
      discovery?: BuildOAuthDiscoveryArgs;
      authorize: OAuthAuthorizeCallback;
      token?: OAuthTokenCallback;
    },
  ];

  const { preemptive, discovery, authorize, token, ...opts } = options;
  const oauthRouter = createRouter({ preemptive });
  const provider = useOAuthProvider(opts);

  const rmBase = sliceBaseUrl(opts.issuer, discovery?.prefix);
  const discoveryDoc = provider.discovery(
    base === undefined
      ? discovery
      : {
          ...discovery,
          prefix: base,
        },
  );

  // OAuth Provider Configuration (Discovery)
  oauthRouter.get(
    "/.well-known/oauth-configuration",
    defineEventHandler(() => {
      return discoveryDoc;
    }),
  );

  // JWKS (public keys)
  oauthRouter.get(
    rmBase(discoveryDoc.jwks_uri),
    defineEventHandler(() => provider.jwkSet),
  );

  // Authorization Endpoint
  oauthRouter.get(
    rmBase(discoveryDoc.authorization_endpoint),
    defineEventHandler(async (event) => {
      return provider.authorize(event, authorize);
    }),
  );

  // Token Endpoint
  oauthRouter.post(
    rmBase(discoveryDoc.token_endpoint),
    defineEventHandler(async (event) => {
      return provider.token(event, token);
    }),
  );

  return base === undefined ? oauthRouter : useBase(base, oauthRouter.handler);
}

function sliceBaseUrl(issuer: string, prefix?: string) {
  const baseUrl = `${issuer.replace(/\/+$/, "")}${
    prefix ? `/${prefix.replace(/^\/+|\/+$/g, "")}` : ""
  }`;

  return (input: string) => input.slice(baseUrl.length);
}
