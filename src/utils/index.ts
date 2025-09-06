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

export function generateJwk<Alg extends GenerateKeyAlgorithm>(
  alg: Alg,
  options: GenerateJWKOptions = {},
): Promise<GenerateJWKReturn<Alg>> {
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

/**
 * Redact a sensitive token for logging: keep prefix and last 4 characters.
 */
export function redactToken(
  token: string,
  options: { prefixLen?: number; suffixLen?: number } = {},
): string {
  const { prefixLen = 6, suffixLen = 4 } = options;
  if (!token) return "<empty>";
  const start = token.slice(0, Math.max(0, prefixLen));
  const end = token.slice(Math.max(0, token.length - suffixLen));
  return `${start}…${end}`;
}
