import type {
  JWK_AES_CBC_HMAC,
  JWK_AES_GCM,
  JWK_AES_GCM_KW,
  JWK_AES_KW,
  JWK_PBES2,
  JWK_Symmetric,
} from "unjwt/session";
import { configError } from "../flow/_internal/http/shared.ts";

/**
 * A key that seals a sign-in's flow, intent and handoff tokens: a symmetric JWK naming its `alg`
 * (what `deriveKey` or `generateJWK("A256GCM")` returns), or a secret `CryptoKey`. Never a key
 * pair: a JWE sealed to a public key proves nothing about who sealed it, so anyone holding that
 * public key could mint a token the sign-in would trust.
 */
export type FlowKey =
  | JWK_Symmetric<JWK_AES_GCM | JWK_AES_KW | JWK_AES_GCM_KW | JWK_AES_CBC_HMAC | JWK_PBES2 | "dir">
  | CryptoKey;

/** The flow key, or a callback returning it, resolved on the first request and kept. */
export type FlowKeyInput = FlowKey | (() => FlowKey | Promise<FlowKey>);

/** The key that seals a sign-in's flow cookie. */
export interface SignInKey {
  /**
   * A symmetric JWE key, or a callback returning one: called on the first request and its key
   * kept for every later one; a rejection is not kept, and the next request calls it again. A
   * random secret goes through `deriveKey`.
   */
  key: FlowKeyInput;
}

/**
 * A resolver of `input`'s flow key, resolved once. A direct key is checked on this call, a
 * callback's key when it resolves: either throws `ERR_UNAUTH_CONFIG_INVALID` for a string,
 * nothing, or a key that is not symmetric.
 */
export function flowKeyResolver(input: FlowKeyInput): () => Promise<FlowKey> {
  if (typeof input !== "function") {
    const resolved = Promise.resolve(assertFlowKey(input));
    return () => resolved;
  }
  let pending: Promise<FlowKey> | undefined;
  return () =>
    (pending ??= Promise.resolve()
      .then(input)
      .then(assertFlowKey)
      .catch((error: unknown) => {
        pending = undefined;
        throw error;
      }));
}

/** `key` once it is a symmetric key unjwt can seal with; `ERR_UNAUTH_CONFIG_INVALID` otherwise. */
function assertFlowKey(key: unknown): FlowKey {
  if (key === undefined || key === null) {
    throw configError(
      "The sign-in needs a flow key: give it a `key` (a symmetric JWE key, or a callback returning one).",
    );
  }
  if (typeof key === "string") {
    throw configError(
      "The sign-in `key` must be a symmetric JWE key, not a string: turn a random secret into one with `deriveKey(secret, { info })`.",
    );
  }
  if (isSecretCryptoKey(key) || isSymmetricJwk(key)) return key;
  throw configError(
    "The sign-in `key` must be symmetric (an `oct` JWK naming its `alg`, such as `deriveKey`'s, or a secret `CryptoKey`): a key pair seals with its public half, which anyone holding it could use to forge sign-in tokens.",
  );
}

function isSecretCryptoKey(key: unknown): key is CryptoKey {
  return typeof CryptoKey !== "undefined" && key instanceof CryptoKey && key.type === "secret";
}

function isSymmetricJwk(key: unknown): key is Exclude<FlowKey, CryptoKey> {
  return (
    typeof key === "object" &&
    key !== null &&
    Reflect.get(key, "kty") === "oct" &&
    typeof Reflect.get(key, "k") === "string" &&
    typeof Reflect.get(key, "alg") === "string"
  );
}
