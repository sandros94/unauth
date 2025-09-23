import type { JWTClaims } from "unjwt";
import { sign } from "unjwt/jws";

import type { IdTokenClaims } from "../../types";
import {
  type TokenErrorResponse,
  type AuthorizationCodeGrantRequest,
  type BuildAuthorizationCodeGrantArgs as OAuthBuildAuthorizationCodeGrantArgs,
  type BuildAuthorizationCodeGrantReturn as OAuthBuildAuthorizationCodeGrantReturn,
  type BuildRefreshTokenGrantArgs as OAuthBuildRefreshTokenGrantArgs,
  type BuildRefreshTokenGrantReturn as OAuthBuildRefreshTokenGrantReturn,
  validateAuthorizationCodeClaims as oauthValidateAuthorizationCodeClaims,
  buildAuthorizationCodeGrant as oauthBuildAuthorizationCodeGrant,
  buildRefreshTokenGrant as oauthBuildRefreshTokenGrant,
  OAuthError,
} from "../../../oauth";
import { type IdTokenOptions, idTokenDefaults } from "./defaults";
import type {
  AuthorizationCodeClaims,
  RefreshTokenClaims,
  TokenSuccessResponse,
} from "../../types";
import { computeTokenHash } from "./utils";

export {
  type BuildClientCredentialsGrantArgs,
  type BuildClientCredentialsGrantReturn,
  buildClientCredentialsGrant,
  validateClientCredentialsGrantRequest,
  validateRefreshTokenClaims,
  validateTokenRequest,
} from "../../../oauth/provider/internal/token";

// #region type definitions

interface BuildIDTokenArgs {
  claims: Omit<IdTokenClaims, "iat" | "exp" | "at_hash">;
  access_token: string;
  options: IdTokenOptions;
  currentDate: Date;
}

export interface BuildAuthorizationCodeGrantArgs
  extends Omit<OAuthBuildAuthorizationCodeGrantArgs, "codeClaims"> {
  codeClaims: AuthorizationCodeClaims;
  idTokenOptions: IdTokenOptions;
  extraIdTokenClaims?: JWTClaims;
}

export interface BuildAuthorizationCodeGrantReturn
  extends OAuthBuildAuthorizationCodeGrantReturn {
  res: TokenSuccessResponse;
  idTokenClaims: IdTokenClaims;
}

export interface BuildRefreshTokenGrantArgs
  extends Omit<
    OAuthBuildRefreshTokenGrantArgs,
    "codeClaims" | "refreshTokenClaims"
  > {
  refreshTokenClaims: RefreshTokenClaims;
  idTokenOptions: IdTokenOptions;
  extraIdTokenClaims?: JWTClaims;
}

export interface BuildRefreshTokenGrantReturn
  extends Omit<OAuthBuildRefreshTokenGrantReturn, "refreshTokenClaims"> {
  res: TokenSuccessResponse;
  idTokenClaims: IdTokenClaims;
  refreshTokenClaims: RefreshTokenClaims;
}

// #endregion

// #region validation functions

export async function validateAuthorizationCodeClaims(args: {
  claims: AuthorizationCodeClaims;
  req: AuthorizationCodeGrantRequest;
  iss: string;
}): Promise<TokenErrorResponse | undefined> {
  const { claims, req, iss } = args;

  // OIDC requirements: ensure nonce presence propagated in codeClaims
  if (!claims.nonce) {
    return new OAuthError({
      error: "invalid_grant",
      error_description: "Missing nonce in authorization code claims",
      iss,
    }).toJSON();
  }

  return oauthValidateAuthorizationCodeClaims({
    claims,
    req,
    iss,
  });
}

// #endregion

// #region Grant-Specific Builders

async function buildIdToken(args: BuildIDTokenArgs): Promise<{
  id_token: string;
  idTokenClaims: IdTokenClaims;
}> {
  const { claims, access_token, options, currentDate } = args;
  const opts = idTokenDefaults(options);
  const alg = opts.privateKey.alg || opts.signOptions.alg;
  if (!alg) {
    throw new Error("[OIDC] JWS alg is required to compute at_hash");
  }

  const at_hash = await computeTokenHash(access_token, alg);

  const iat = Math.floor(currentDate.getTime() / 1000);

  const idTokenClaims: IdTokenClaims = {
    ...claims,
    iat,
    exp: iat + opts.signOptions.expiresIn,
    at_hash,
  } as IdTokenClaims;

  const id_token = await sign(idTokenClaims, opts.privateKey, {
    ...opts.signOptions,
  });

  return { id_token, idTokenClaims };
}

export async function buildAuthorizationCodeGrant(
  args: BuildAuthorizationCodeGrantArgs,
): Promise<BuildAuthorizationCodeGrantReturn | TokenErrorResponse> {
  const {
    req,
    codeClaims,
    accessTokenOptions,
    refreshTokenOptions,
    idTokenOptions,
    extraAccessTokenClaims,
    extraRefreshTokenClaims,
    extraIdTokenClaims,
    iss,
    randomJti,
    currentDate,
  } = args;

  // Build OAuth tokens first
  const {
    res: oauthRes,
    accessTokenClaims,
    refreshTokenClaims,
  } = await oauthBuildAuthorizationCodeGrant({
    req,
    codeClaims,
    accessTokenOptions,
    refreshTokenOptions,
    extraAccessTokenClaims,
    extraRefreshTokenClaims: {
      ...extraRefreshTokenClaims,
      ...(codeClaims.nonce ? { nonce: codeClaims.nonce } : {}),
    },
    iss,
    randomJti,
    currentDate,
  });

  // Then build ID Token
  const { id_token, idTokenClaims } = await buildIdToken({
    claims: {
      ...extraIdTokenClaims,
      iss,
      aud: accessTokenClaims.aud,
      sub: accessTokenClaims.sub,
      nonce: codeClaims.nonce,
    },
    access_token: oauthRes.access_token,
    options: idTokenOptions,
    currentDate,
  });

  return {
    res: { ...oauthRes, id_token },
    accessTokenClaims,
    refreshTokenClaims,
    idTokenClaims,
  };
}

export async function buildRefreshTokenGrant(
  args: BuildRefreshTokenGrantArgs,
): Promise<BuildRefreshTokenGrantReturn | TokenErrorResponse> {
  const {
    req,
    refreshTokenClaims: oldRTClaims,
    idTokenOptions,
    accessTokenOptions,
    refreshTokenOptions,
    extraIdTokenClaims,
    extraAccessTokenClaims,
    extraRefreshTokenClaims,
    iss,
    randomJti,
    currentDate,
  } = args;

  // Build OAuth tokens first
  const {
    res: oauthRes,
    accessTokenClaims,
    refreshTokenClaims,
  } = await oauthBuildRefreshTokenGrant({
    req,
    refreshTokenClaims: oldRTClaims,
    accessTokenOptions,
    refreshTokenOptions,
    extraAccessTokenClaims,
    extraRefreshTokenClaims: {
      ...extraRefreshTokenClaims,
      ...(oldRTClaims.nonce ? { nonce: oldRTClaims.nonce } : {}),
    },
    iss,
    randomJti,
    currentDate,
  });

  // Then build ID Token
  const { id_token, idTokenClaims } = await buildIdToken({
    claims: {
      ...extraIdTokenClaims,
      iss,
      aud: accessTokenClaims.aud,
      sub: accessTokenClaims.sub,
      ...(oldRTClaims.nonce ? { nonce: oldRTClaims.nonce } : {}),
    },
    access_token: oauthRes.access_token,
    options: idTokenOptions,
    currentDate,
  });

  return {
    res: { ...oauthRes, id_token },
    accessTokenClaims,
    refreshTokenClaims,
    idTokenClaims,
  };
}

// #endregion
