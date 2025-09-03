import type { JWK, JWSSignOptions, JWSVerifyOptions } from "unjwt";

import { type OAuthProviderConfig, OAuthProvider } from "../oauth/service";

export interface OIDCProviderConfig extends OAuthProviderConfig {
  /**
   * Options for ID Tokens.
   */
  idToken?: { signOptions?: JWSSignOptions; verifyOptions?: JWSVerifyOptions };
}

export class OIDCProvider {
  readonly oauth: OAuthProvider;

  constructor(
    private readonly config: OIDCProviderConfig & {
      issuer: string;
      jwsKey: JWK;
    },
  ) {
    // Reuse OAuth service for token/authorize utilities
    const { idToken: _, ...oauthCfg } = config;
    this.oauth = new OAuthProvider(oauthCfg);
  }
}
