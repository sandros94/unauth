import type {
  GenerateKeyAlgorithm,
  GenerateKeyOptions,
  JWKParameters,
  JWK_Asymmetric_Algorithm,
  JWK,
} from "unjwt";
import { generateKey } from "unjwt/jwk";

export { importJWKFromPEM } from "unjwt/jwk";

export interface GenerateJWKOptions extends Omit<GenerateKeyOptions, "toJWK"> {
  params?: Omit<JWKParameters, "alg" | "kty" | "key_ops" | "ext">;
}

export type GenerateJWKReturn<Alg extends GenerateKeyAlgorithm> =
  Alg extends JWK_Asymmetric_Algorithm
    ? {
        privateKey: JWK;
        publicKey: JWK;
      }
    : JWK;

export function generateJwk(
  alg: GenerateKeyAlgorithm,
  options: GenerateJWKOptions = {},
): Promise<GenerateJWKReturn<typeof alg>> {
  const {
    // @ts-expect-error destructuring just to avoid passing it down
    toJWK: _,
    params,
    ...opts
  } = options;

  return generateKey(alg, {
    ...opts,
    toJWK: (params as object) || true,
  });
}
