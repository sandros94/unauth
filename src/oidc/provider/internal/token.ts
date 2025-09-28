import { computeExpiresInSeconds } from "unjwt/utils";
import type { JWTClaims } from "unjwt";
import { sign } from "unjwt/jws";

import type { IdTokenClaims } from "../../types";
import {
  type AuthorizationCodeGrantRequest,
  type RefreshTokenGrantRequest,
  type BuildAuthorizationCodeGrantArgs as OAuthBuildAuthorizationCodeGrantArgs,
  type BuildAuthorizationCodeGrantReturn as OAuthBuildAuthorizationCodeGrantReturn,
  type BuildRefreshTokenGrantArgs as OAuthBuildRefreshTokenGrantArgs,
  type BuildRefreshTokenGrantReturn as OAuthBuildRefreshTokenGrantReturn,
  validateTokenRequest as oauthValidateTokenRequest,
  validateAuthorizationCodeGrantRequest as oauthValidateAuthorizationCodeGrantRequest,
  validateAuthorizationCodeClaims as oauthValidateAuthorizationCodeClaims,
  validateRefreshTokenClaims as oauthValidateRefreshTokenClaims,
  buildAuthorizationCodeGrant as oauthBuildAuthorizationCodeGrant,
  buildRefreshTokenGrant as oauthBuildRefreshTokenGrant,
  introspectAuthorizationCode,
  introspectRefreshToken,
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
  validateTokenRequest,
} from "../../../oauth/provider/internal/token";

// #region type definitions

interface BuildIDTokenArgs {
  claims: Omit<IdTokenClaims, "iat" | "exp" | "at_hash">;
  access_token: string;
  options: IdTokenOptions;
  currentDate?: Date;
}

export interface BuildAuthorizationCodeGrantArgs
  extends Omit<OAuthBuildAuthorizationCodeGrantArgs, "req"> {
  req: Omit<AuthorizationCodeGrantRequest, "code"> & {
    code: string | AuthorizationCodeClaims;
  };
  idTokenOptions: IdTokenOptions;
  extraIdTokenClaims?: JWTClaims;
}

export interface BuildAuthorizationCodeGrantReturn
  extends OAuthBuildAuthorizationCodeGrantReturn {
  res: TokenSuccessResponse;
  idTokenClaims: IdTokenClaims;
}

export interface BuildRefreshTokenGrantArgs
  extends Omit<OAuthBuildRefreshTokenGrantArgs, "req"> {
  req: Omit<RefreshTokenGrantRequest, "refresh_token"> & {
    refresh_token: string | RefreshTokenClaims;
  };
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
  req: Pick<AuthorizationCodeGrantRequest, "client_id" | "code_verifier">;
  iss: string;
}): Promise<void> {
  const { claims, req, iss } = args;

  // OIDC requirements: ensure nonce presence propagated in codeClaims
  if (!claims.nonce) {
    throw new OAuthError({
      error: "invalid_grant",
      error_description: "Missing nonce in authorization code claims",
      iss,
    });
  }

  await oauthValidateAuthorizationCodeClaims({
    claims,
    req,
    iss,
  });
}

export async function validateRefreshTokenClaims(args: {
  claims: RefreshTokenClaims;
  req: Pick<RefreshTokenGrantRequest, "client_id" | "scope">;
  iss: string;
}): Promise<void> {
  const { claims, req, iss } = args;

  // OIDC requirements: ensure nonce presence propagated in codeClaims
  if (!claims.nonce) {
    throw new OAuthError({
      error: "invalid_grant",
      error_description: "Missing nonce in authorization code claims",
      iss,
    });
  }

  await oauthValidateRefreshTokenClaims({
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
  const { claims, access_token, options } = args;
  const opts = idTokenDefaults(options);
  const alg = opts.privateKey.alg || opts.signOptions.alg;
  if (!alg) {
    throw new Error("[OIDC] JWS alg is required to compute at_hash");
  }

  const at_hash = await computeTokenHash(access_token, alg);

  const currentDate =
    (args.currentDate || opts.signOptions.currentDate) ?? new Date();
  const iat = Math.floor(currentDate.getTime() / 1000);

  const idTokenClaims: IdTokenClaims = {
    ...claims,
    iat,
    exp: iat + computeExpiresInSeconds(opts.signOptions.expiresIn),
    at_hash,
  } as IdTokenClaims;

  const id_token = await sign(idTokenClaims, opts.privateKey, {
    ...opts.signOptions,
    protectedHeader: { ...opts.signOptions.protectedHeader, typ: "id+jwt" },
    currentDate,
  });

  return { id_token, idTokenClaims };
}

export async function buildAuthorizationCodeGrant(
  args: BuildAuthorizationCodeGrantArgs,
): Promise<BuildAuthorizationCodeGrantReturn> {
  const {
    req,
    authorizationCodeOptions,
    accessTokenOptions,
    refreshTokenOptions,
    idTokenOptions,
    extraAccessTokenClaims,
    extraRefreshTokenClaims,
    extraIdTokenClaims,
    iss,
    randomJti,
    currentDate = new Date(),
  } = args;

  oauthValidateTokenRequest(req, iss);
  oauthValidateAuthorizationCodeGrantRequest(req, iss);

  const codeClaims =
    typeof req.code === "string"
      ? (
          await introspectAuthorizationCode<AuthorizationCodeClaims>({
            token: req.code,
            iss,
            options: authorizationCodeOptions,
          })
        ).payload
      : req.code;

  // Validate authorization code claims
  await validateAuthorizationCodeClaims({
    claims: codeClaims,
    req,
    iss,
  });

  // Build OAuth tokens first
  const {
    res: oauthRes,
    accessTokenClaims,
    refreshTokenClaims,
  } = await oauthBuildAuthorizationCodeGrant({
    req: {
      ...req,
      code: codeClaims, // pass the claims to avoid double introspection
    },
    authorizationCodeOptions,
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
): Promise<BuildRefreshTokenGrantReturn> {
  const {
    req,
    idTokenOptions,
    accessTokenOptions,
    refreshTokenOptions,
    extraIdTokenClaims,
    extraAccessTokenClaims,
    extraRefreshTokenClaims,
    iss,
    randomJti,
    currentDate = new Date(),
  } = args;

  const oldRTClaims =
    typeof req.refresh_token === "string"
      ? (
          await introspectRefreshToken<RefreshTokenClaims>({
            token: req.refresh_token,
            iss,
            options: refreshTokenOptions,
          })
        ).payload
      : req.refresh_token;

  // Validate refresh token claims
  await validateRefreshTokenClaims({
    claims: oldRTClaims,
    req,
    iss,
  });

  // Build OAuth tokens first
  const {
    res: oauthRes,
    accessTokenClaims,
    refreshTokenClaims,
  } = await oauthBuildRefreshTokenGrant({
    req: {
      ...req,
      refresh_token: oldRTClaims, // pass the claims to avoid double introspection
    },
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
