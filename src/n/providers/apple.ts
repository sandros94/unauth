import { importPEM } from "unjwt/jwk";
import { type JWSSignJWK, sign } from "unjwt/jws";
import { safeJsonParse } from "unsecure/sanitize";
import { isRecord, profileError } from "../flow/_internal/http/shared.ts";
import { defineProvider } from "../flow/provider.ts";
import type { ProfileContext, ProfileResult, OAuthProvider } from "../flow/types.ts";
import type { WebRequestEvent } from "../request-event.ts";
import {
  type PresetConfig,
  type PresetHandler,
  type PresetHandlerConfig,
  presetHandler,
  booleanClaim,
  nonEmpty,
} from "./_internal/shared.ts";

/** What Apple posts as `user` on the first authorization only. */
export interface AppleUser {
  name?: { firstName?: string; lastName?: string };
  email?: string;
}

/**
 * Apple's id_token claims (https://developer.apple.com/documentation/signinwithapple/authenticating-users-with-sign-in-with-apple),
 * plus the first-login `user` form field when it came.
 */
export interface AppleProfile {
  sub: string;
  email?: string;
  email_verified?: boolean | "true" | "false";
  is_private_email?: boolean | "true" | "false";
  real_user_status?: number;
  auth_time?: number;
  nonce_supported?: boolean;
  /** Present on the first sign-in only; unverified, as it passes through the browser. */
  user?: AppleUser;
}

/** Options of {@link defineAppleProvider}. */
export interface AppleProviderConfig extends PresetConfig {
  /** The Services ID. */
  clientId: string;
  teamId: string;
  /** The id of the Sign in with Apple key. */
  keyId: string;
  /** That key: the `.p8` PKCS#8 PEM, or its JWK. */
  privateKey: string | JWSSignJWK;
}

const APPLE = "https://appleid.apple.com";
/** Seconds a minted client secret is valid; Apple accepts up to six months. */
const SECRET_LIFETIME = 300;

/**
 * Sign in with Apple, OpenID Connect on `https://appleid.apple.com`: authorization
 * `/auth/authorize`, token `/auth/token`, keys `/auth/keys`. The callback is a `form_post`, which
 * Apple requires whenever scopes are requested. No PKCE: `state` and the id_token's `nonce` protect
 * the flow. The client secret, sent in the request body, is an ES256 JWT minted per token request
 * and valid five minutes. Apple's scopes are `name` and `email`, without `openid`; the id_token
 * comes all the same. The name arrives only on the first sign-in, in the posted `user` field.
 *
 * @default scopes `["name", "email"]`
 */
export function defineAppleProvider(options: AppleProviderConfig): OAuthProvider<AppleProfile> {
  return defineProvider({
    id: options.id ?? "apple",
    label: options.label ?? "Apple",
    kind: "oidc",
    issuer: APPLE,
    authorization: `${APPLE}/auth/authorize`,
    token: `${APPLE}/auth/token`,
    jwks: `${APPLE}/auth/keys`,
    responseMode: "form_post",
    pkce: false,
    tokenAuth: "body",
    scopes: options.scopes ?? ["name", "email"],
    openidScope: false,
    authorizationParams: options.authorizationParams,
    client: { id: options.clientId, secret: appleClientSecret(options) },
    profile: appleProfile,
  });
}

/** Options of {@link defineAppleHandler}: {@link AppleProviderConfig} and `defineSignInHandler`'s, in one object. */
export type AppleHandlerConfig<
  TResult = never,
  TEvent extends WebRequestEvent = WebRequestEvent,
  TLink = never,
> = PresetHandlerConfig<AppleProviderConfig, AppleProfile, TResult, TEvent, TLink>;

/**
 * Both legs of an Apple sign-in on one route: `defineSignInHandler` on {@link defineAppleProvider}, the
 * options split between them by the provider's keys.
 */
export const defineAppleHandler: PresetHandler<AppleProviderConfig, AppleProfile> =
  /* @__PURE__ */ presetHandler(defineAppleProvider, {
    keys: [
      "clientId",
      "teamId",
      "keyId",
      "privateKey",
      "scopes",
      "authorizationParams",
      "id",
      "label",
    ],
  });

/** Mints Apple's client secret: an ES256 JWT from the team to `appleid.apple.com`. */
export function appleClientSecret(
  options: Pick<AppleProviderConfig, "clientId" | "teamId" | "keyId" | "privateKey">,
): () => Promise<string> {
  let key: Promise<JWSSignJWK> | undefined;
  return async () => {
    key ??=
      typeof options.privateKey === "string"
        ? importPEM(options.privateKey, "ES256", {
            pemType: "pkcs8",
            jwkParams: { kid: options.keyId },
          })
        : Promise.resolve({ ...options.privateKey, kid: options.keyId });
    const iat = Math.floor(Date.now() / 1000);
    return sign(
      { iss: options.teamId, sub: options.clientId, aud: APPLE, iat, exp: iat + SECRET_LIFETIME },
      await key,
      { alg: "ES256" },
    );
  };
}

function appleProfile(context: ProfileContext): ProfileResult<AppleProfile> {
  const { claims } = context;
  if (!claims) throw profileError("The Apple sign-in carried no id_token claims.");
  const user = firstLoginUser(context.params.user);
  const profile: AppleProfile = { ...claims, ...(user ? { user } : {}) };
  const result: ProfileResult<AppleProfile> = { subject: claims.sub, profile };
  const email = nonEmpty(claims.email);
  if (email !== undefined) result.email = email;
  const verified = booleanClaim(claims.email_verified);
  if (verified !== undefined) result.emailVerified = verified;
  const name = [user?.name?.firstName, user?.name?.lastName].filter(Boolean).join(" ");
  if (name) result.name = name;
  return result;
}

/** The posted `user` JSON, when it parses into the documented shape. */
function firstLoginUser(raw: string | undefined): AppleUser | undefined {
  if (!raw) return undefined;
  let parsed: unknown;
  try {
    parsed = safeJsonParse(raw);
  } catch {
    return undefined;
  }
  if (!isRecord(parsed)) return undefined;
  const name = isRecord(parsed.name) ? parsed.name : undefined;
  const user: AppleUser = {};
  const firstName = nonEmpty(name?.firstName);
  const lastName = nonEmpty(name?.lastName);
  if (firstName !== undefined || lastName !== undefined) user.name = { firstName, lastName };
  const email = nonEmpty(parsed.email);
  if (email !== undefined) user.email = email;
  return user;
}
