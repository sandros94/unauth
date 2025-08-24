import { sign } from "unjwt/jws";
import { hash } from "unsecure";
import { base64UrlEncode } from "unjwt/utils";
import type { DigestAlgorithm } from "unsecure";
import type { JWK, JWSSignOptions, JWTClaims } from "unjwt";

/**
 * Configuration for the OIDCProvider class.
 */
export interface OIDCProviderConfig {
  /**
   * The Issuer Identifier URL for the provider.
   * This is a REQUIRED value in the ID Token.
   */
  issuer: string;
  /**
   * An array of private keys in JWK format used for signing tokens.
   */
  privateKeys: JWK[];
  /**
   * An array of public keys in JWK format used for verifying tokens.
   */
  publicKeys: JWK[];
}

/**
 * Standard claims for an OpenID Connect UserInfo response.
 */
export interface UserInfoClaims extends JWTClaims {
  sub: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  middle_name?: string;
  nickname?: string;
  preferred_username?: string;
  profile?: string;
  picture?: string;
  website?: string;
  email?: string;
  email_verified?: boolean;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  phone_number?: string;
  phone_number_verified?: boolean;
  address?: object;
  updated_at?: number;
}

/**
 * Standard and custom claims for an OpenID Connect ID Token.
 */
export interface IdTokenClaims extends UserInfoClaims {
  // Standard OIDC claims from Section 2 of the spec
  acr?: string;
  amr?: string[];
  azp?: string;
  auth_time?: number;
  nonce?: string;
}

/**
 * A class to manage OIDC Provider operations.
 */
export class OIDCProvider {
  public readonly config: OIDCProviderConfig;

  constructor(config: OIDCProviderConfig) {
    this.config = config;
  }

  /**
   * Returns the public keys from the configuration as a JWKSet.
   * This is intended for use in a JWKS endpoint (`.well-known/jwks-uri`).
   */
  public get jwks(): { keys: Array<JWK> } {
    return {
      keys: this.config.publicKeys,
    };
  }

  /**
   * Creates and signs an ID Token.
   *
   * @param claims - The claims to include in the ID Token. `sub`, `aud`, `exp`, and `iat` are required.
   * @param privateKeyJwk - The private key from the config to use for signing.
   * @returns A promise that resolves to the signed ID Token (JWS string).
   */
  public async createIdToken(
    claims: IdTokenClaims,
    privateKeyJwk: JWK,
    options?: JWSSignOptions,
  ): Promise<string> {
    const payload: IdTokenClaims = {
      ...claims,
      iss: this.config.issuer,
      iat: Math.floor(Date.now() / 1000),
    };

    return await sign(payload, privateKeyJwk, options);
  }

  /**
   * Creates a UserInfo response object.
   * In a real implementation, this could also sign/encrypt the response.
   *
   * @param claims - The user info claims.
   * @returns A JSON object ready to be sent as the UserInfo response.
   */
  public createUserInfoResponse(claims: UserInfoClaims): UserInfoClaims {
    // This could be extended to sign/encrypt the response into a JWT
    // using `unjwt.sign` or `unjwt.encrypt`
    return claims;
  }

  /**
   * Calculates the `at_hash` for an Access Token.
   *
   * @param accessToken - The OAuth 2.0 Access Token.
   * @param signingAlg - The JWS `alg` algorithm used to sign the ID Token (e.g., 'RS256').
   * @returns A promise that resolves to the `at_hash` string.
   */
  public async calculateAtHash(
    accessToken: string,
    signingAlg: DigestAlgorithm,
  ): Promise<string> {
    const hashed = await hash(accessToken, { algorithm: signingAlg });
    const half = hashed.slice(0, hashed.length / 2); // Take the left-most half
    return base64UrlEncode(half);
  }

  /**
   * Calculates the `c_hash` for an Authorization Code.
   *
   * @param code - The OAuth 2.0 Authorization Code.
   * @param signingAlg - The JWS `alg` algorithm used to sign the ID Token (e.g., 'RS256').
   * @returns A promise that resolves to the `c_hash` string.
   */
  public async calculateCHash(
    code: string,
    signingAlg: DigestAlgorithm,
  ): Promise<string> {
    const hashed = await hash(code, {
      algorithm: signingAlg,
      returnAs: "bytes",
    });
    const half = hashed.slice(0, hashed.length / 2); // Take the left-most half
    return base64UrlEncode(half);
  }
}
