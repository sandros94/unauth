import type { SessionConfigJWE } from "unjwt/session";
import { configError } from "./flow/_http.ts";

/** A key unjwt's JWE session seals with: a symmetric JWK, a `CryptoKey`, or an asymmetric pair. */
export type FlowKey = SessionConfigJWE["key"];

/** The flow key, or a callback returning it, resolved on the first request and kept. */
export type FlowKeyInput = FlowKey | (() => FlowKey | Promise<FlowKey>);

/** The key that seals a sign-in's flow cookie. */
export interface SignInKey {
  /**
   * A JWE key, or a callback returning one: called on the first request, its key kept for every
   * later one, a failure not kept so the next request calls it again. A passphrase goes through
   * `deriveKey`, a PEM through unjwt's `importPEM(pem, alg)`.
   */
  key: FlowKeyInput;
}

/**
 * The flow key of `input`, resolved once. A direct key is checked here, so a misconfiguration
 * throws where the route is defined; a callback's key is checked when it resolves.
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

/** `key` once it is one unjwt can seal with; `ERR_UNAUTH_CONFIG_INVALID` for a string or nothing. */
function assertFlowKey(key: FlowKey | string | null | undefined): FlowKey {
  if (key === undefined || key === null) {
    throw configError(
      "The sign-in needs a flow key: give it a `key` (a JWE key, or a callback returning one).",
    );
  }
  if (typeof key === "string") {
    throw configError(
      "The sign-in `key` must be a JWE key, not a string: import a PEM with `importPEM(pem, alg)` from unjwt, or turn a passphrase into a key with `deriveKey(secret, { info })`.",
    );
  }
  return key;
}
