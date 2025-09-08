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

/**
 * Merges two arrays while avoiding duplicates based on a predicate function.
 *
 * @template T - Type of the first array
 * @template U - Type of the second array
 * @param {T} a - First array
 * @param {U} b - Second array to merge into the first
 * @param {function(T[number], U[number]): boolean} predicate - Function to determine if two items are equal
 *                                                            - Defaults to strict equality (===)
 * @returns {Array<T[number] | U[number]>} A new array containing all items from the first array
 *                                         and non-duplicate items from the second array
 *
 * @example
 * // Basic usage with default predicate
 * mergeArrays([1, 2, 3], [2, 3, 4]) // returns [1, 2, 3, 4]
 *
 * @example
 * // With custom predicate for object arrays
 * mergeArrays(
 *   [{id: 1}, {id: 2}],
 *   [{id: 2}, {id: 3}],
 *   (a, b) => a.id === b.id
 * ) // returns [{id: 1}, {id: 2}, {id: 3}]
 */
export function mergeArrays<
  T extends Array<unknown> | ReadonlyArray<unknown>,
  U extends Array<unknown> | ReadonlyArray<unknown>,
>(
  a: T,
  b: U,
  predicate: (aN: T[number], bN: U[number]) => boolean = (
    a: T[number],
    b: U[number],
  ) => a === b,
): Array<T[number] | U[number]> {
  const _a = [...a];
  // eslint-disable-next-line unicorn/no-array-for-each
  b.forEach((bItem: U[number]) =>
    _a.some((aItem: T[number]) => predicate(aItem, bItem))
      ? null
      : _a.push(bItem),
  );
  return _a;
}
