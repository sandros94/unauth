import { computeExpiresInSeconds } from "unjwt/utils";
import { sign } from "unjwt/jws";

import type {
  Result,
  TokenSuccessResponse,
  AccessTokenClaims,
  IdTokenClaims,
  TokenErrorResponse,
} from "../../types";
import {
  type NormalizedAuthorizationCodeGrantInput as OAuthNormalizedAuthorizationCodeGrantInput,
  type NormalizedRefreshTokenGrantInput as OAuthNormalizedRefreshTokenGrantInput,
  type NormalizedClientCredentialsGrantInput,
  type IssueTokenGrantOptions as OAuthIssueTokenGrantOptions,
  type IssueClientCredentialsGrantReturn,
  issueAuthorizationCodeGrant as oauthIssueAuthorizationCodeGrant,
  issueRefreshTokenGrant as oauthIssueRefreshTokenGrant,
  introspectAuthorizationCode,
  introspectRefreshToken,
} from "../../../oauth";
import { type IdTokenOptions, idTokenDefaults } from "./defaults";
import type { AuthorizationCodeClaims, RefreshTokenClaims } from "../../types";
import { computeTokenHash } from "./utils";

export {
  type TokenGrantType,
  type NormalizedClientCredentialsGrantInput,
  type IssueClientCredentialsGrantReturn,
  validateTokenGrantType,
  issueClientCredentialsGrant,
} from "../../../oauth/provider/internal/token";

// #region types

export interface NormalizedAuthorizationCodeGrantInput
  extends OAuthNormalizedAuthorizationCodeGrantInput {
  idTokenExtraClaims?: Record<string, unknown>;
}

export interface NormalizedRefreshTokenGrantInput
  extends OAuthNormalizedRefreshTokenGrantInput {
  idTokenExtraClaims?: Record<string, unknown>;
}

export type NormalizedTokenInput =
  | NormalizedAuthorizationCodeGrantInput
  | NormalizedRefreshTokenGrantInput
  | NormalizedClientCredentialsGrantInput;

export interface IssueTokenGrantOptions extends OAuthIssueTokenGrantOptions {
  idTokenOptions: IdTokenOptions;
}

export type IssueAuthorizationCodeGrantReturn = Result<
  TokenSuccessResponse,
  {
    accessTokenClaims: AccessTokenClaims;
    refreshTokenClaims: RefreshTokenClaims;
    idTokenClaims: IdTokenClaims;
  },
  TokenErrorResponse
>;

export type IssueRefreshTokenGrantReturn = Result<
  TokenSuccessResponse,
  {
    accessTokenClaims: AccessTokenClaims;
    refreshTokenClaims: RefreshTokenClaims;
    idTokenClaims: IdTokenClaims;
  },
  TokenErrorResponse
>;

export type IssueTokenGrantReturn =
  | IssueAuthorizationCodeGrantReturn
  | IssueClientCredentialsGrantReturn
  | IssueRefreshTokenGrantReturn;

interface BuildIDTokenArgs {
  claims: Omit<IdTokenClaims, "iat" | "exp" | "at_hash">;
  access_token: string;
  options: IdTokenOptions;
  currentDate?: Date;
}

// #endregion types

// #region internals

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

// #endregion internals

// #region runtime

export async function issueAuthorizationCodeGrant(
  args: NormalizedAuthorizationCodeGrantInput,
  options: IssueTokenGrantOptions,
): Promise<IssueAuthorizationCodeGrantReturn> {
  const { iss, authorizationCodeOptions, idTokenOptions, currentDate } =
    options;

  const codeClaims =
    typeof args.code === "string"
      ? await introspectAuthorizationCode<AuthorizationCodeClaims>({
          token: args.code,
          iss,
          options: authorizationCodeOptions,
        })
      : args.code;

  // Build OAuth tokens first
  const oauthRes = await oauthIssueAuthorizationCodeGrant(
    {
      ...args,
      code: codeClaims,
      refreshTokenExtraClaims: {
        ...args.refreshTokenExtraClaims,
        ...(codeClaims.nonce ? { nonce: codeClaims.nonce } : {}),
      },
    },
    options,
  );

  if (!oauthRes.success) {
    return { success: false, error: oauthRes.error };
  }
  const { access_token, refresh_token, expires_in } = oauthRes.value;
  const { accessTokenClaims, refreshTokenClaims } = oauthRes.artifacts!;

  // Then build ID Token
  const { id_token, idTokenClaims } = await buildIdToken({
    claims: {
      ...args.idTokenExtraClaims,
      iss,
      aud: args.client_id,
      sub: accessTokenClaims.sub,
      nonce: codeClaims.nonce,
    },
    access_token,
    options: idTokenOptions,
    currentDate,
  });

  return {
    success: true,
    value: {
      access_token,
      token_type: "Bearer",
      expires_in,
      scope: accessTokenClaims.scope,
      refresh_token,
      id_token,
    },
    artifacts: {
      accessTokenClaims: accessTokenClaims,
      refreshTokenClaims: refreshTokenClaims,
      idTokenClaims,
    },
  };
}

export async function issueRefreshTokenGrant(
  args: NormalizedRefreshTokenGrantInput,
  options: IssueTokenGrantOptions,
): Promise<IssueRefreshTokenGrantReturn> {
  const { iss, refreshTokenOptions, idTokenOptions, currentDate } = options;

  const oldRTClaims =
    typeof args.refresh_token === "string"
      ? await introspectRefreshToken<RefreshTokenClaims>({
          token: args.refresh_token,
          iss,
          options: refreshTokenOptions,
        })
      : args.refresh_token;

  // Build OAuth tokens first
  const oauthRes = await oauthIssueRefreshTokenGrant(
    {
      ...args,
      refresh_token: oldRTClaims,
      refreshTokenExtraClaims: {
        ...args.refreshTokenExtraClaims,
        ...(oldRTClaims.nonce ? { nonce: oldRTClaims.nonce } : {}),
      },
    },
    options,
  );

  if (!oauthRes.success) {
    return { success: false, error: oauthRes.error };
  }
  const { access_token, refresh_token, expires_in, scope } = oauthRes.value;
  const { accessTokenClaims, refreshTokenClaims } = oauthRes.artifacts!;

  // Then build ID Token
  const { id_token, idTokenClaims } = await buildIdToken({
    claims: {
      ...args.idTokenExtraClaims,
      iss,
      aud: args.client_id,
      sub: accessTokenClaims.sub,
      nonce: oldRTClaims.nonce,
    },
    access_token,
    options: idTokenOptions,
    currentDate,
  });

  return {
    success: true,
    value: {
      access_token,
      token_type: "Bearer",
      expires_in,
      scope,
      refresh_token,
      id_token,
    },
    artifacts: {
      accessTokenClaims,
      refreshTokenClaims,
      idTokenClaims,
    },
  };
}

// #endregion
