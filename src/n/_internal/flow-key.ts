import type {
  ContentEncryptionAlgorithm,
  ExpiresIn,
  JWESessionKey,
  JWESessionKeyLookup,
  JWKSet,
  KeyManagementAlgorithm,
  SessionClaims,
  SessionDecryptOptions,
  SessionEncryptOptions,
} from "unjwt/session";
import { configError } from "../flow/_internal/http/shared.ts";
import { isRecord } from "../../_internal/shared.ts";

/**
 * A key that seals a sign-in's flow, intent and handoff tokens, as unjwt's JWE session takes it:
 * an `oct` JWK (what `deriveJWK` or `generateJWK("A256GCM")` returns, the suggested path), a
 * secret `CryptoKey`, or a JWK Set of `oct` JWKs. A set's first key seals and every key opens: to
 * rotate, put the new key first and keep the old ones after it while the flow cookies, intents and
 * handoffs they sealed may still arrive. A key naming no algorithm (a `CryptoKey`, an `oct` JWK
 * without `alg`, a set entry without one) needs `jwe`. Never a key pair, nor a public JWK: a JWE
 * sealed to a public key proves nothing about who sealed it.
 */
export type FlowKey = JWESessionKey;

/** The flow key, or a callback returning it, resolved on the first request and kept. */
export type FlowKeyInput = FlowKey | (() => FlowKey | Promise<FlowKey>);

/**
 * The JWE algorithms a flow key seals with: required when a key names none (a `CryptoKey`, an
 * `oct` JWK without `alg`). Its `alg` is also the one a key naming none opens tokens under, the
 * keys `onKeyLookup` returns included.
 */
export interface FlowKeyAlgorithms {
  alg: KeyManagementAlgorithm;
  enc: ContentEncryptionAlgorithm;
}

/**
 * The event a flow cookie is read with: the request, the headers unauth collects the response's
 * flow cookie on, and the framework's per-request context when there is one.
 */
export interface FlowEvent {
  req: Request;
  res: { headers: Headers };
  context?: Record<string, unknown>;
}

/**
 * Picks the key that opens an incoming flow cookie, intent or handoff from its protected header
 * (its `kid`, `alg`, `enc`): an `oct` JWK, a secret `CryptoKey` or a JWK Set, for keys kept
 * elsewhere (a KMS, a remote set). It replaces `key` for opening; `key` still seals. A key it
 * returns naming no `alg` opens tokens sealed under `jwe.alg`.
 *
 * Beside `header`, a flow cookie's lookup gets the `event` the cookie is read with, to pick a key
 * from the request (a tenant's, by host); an intent's or a handoff's gets none. unjwt's session
 * `config` is never handed over. What the lookup throws propagates as it is, an `UnauthError`
 * included, so a key store outage reaches the framework as its own error, and a key it returns
 * that cannot open the token rejects with unjwt's `ERR_JWK_INVALID`; to refuse the token instead,
 * return `undefined`: `ERR_AUTHN_FLOW_EXPIRED`.
 */
export type FlowKeyLookup = (
  args: Pick<
    Parameters<JWESessionKeyLookup<SessionClaims, ExpiresIn | undefined, FlowEvent>>[0],
    "header" | "event"
  >,
) => ReturnType<JWESessionKeyLookup>;

/** The key that seals a sign-in's flow cookie. */
export interface SignInKey {
  /**
   * The flow key, or a callback returning one: called on the first request and its key kept for
   * every later one; a rejection is not kept, and the next request calls it again. An `oct` JWK
   * naming its `alg` is the suggested key: `deriveJWK` turns a random secret into one. A secret
   * `CryptoKey`, or a JWK naming no `alg`, needs `jwe`, its `alg` and `enc`. A JWK Set seals with
   * its first key and opens with every one, so the sign-ins in progress survive a key rotation
   * that puts the new key first.
   */
  key: FlowKeyInput;
}

/** What a JWE session sealing sign-in tokens takes beside its key. */
export interface FlowSessionOptions {
  jwe: { encryptOptions: SessionEncryptOptions; decryptOptions?: SessionDecryptOptions };
  hooks?: { onKeyLookup: FlowKeyLookup };
}

/**
 * A resolver of `input`'s flow key, resolved once. A direct key is checked on this call, a
 * callback's key when it resolves: either throws `ERR_UNAUTH_CONFIG_INVALID` for a string,
 * nothing, a key that is not symmetric, or a JWK Set that is empty or holds a key that is not an
 * `oct` JWK.
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

/**
 * The session options of tokens sealed under `key` with their `typ`: `jwe`'s algorithms pinned
 * beside it and named as those a key without `alg` opens, and `onKeyLookup` installed as the
 * session's hook, handed the token's `header` and the `event` when there is one, never unjwt's
 * session `config`. `ERR_UNAUTH_CONFIG_INVALID` when a key (`key`, or an entry of its set) names
 * no algorithm and `jwe` is absent.
 */
export function flowSessionOptions(
  key: FlowKey,
  options: { typ: string; jwe?: FlowKeyAlgorithms; onKeyLookup?: FlowKeyLookup },
): FlowSessionOptions {
  const { typ, jwe, onKeyLookup } = options;
  const keys: unknown[] = isRecord(key) && Array.isArray(key.keys) ? key.keys : [key];
  if (!keys.every(namesAlgorithm) && !(jwe?.alg && jwe.enc)) {
    throw configError('A sign-in key naming no algorithm needs "jwe": its "alg" and "enc".');
  }
  const protectedHeader = { typ };
  const sealing: FlowSessionOptions = jwe
    ? {
        jwe: {
          encryptOptions: { protectedHeader, alg: jwe.alg, enc: jwe.enc },
          decryptOptions: { algorithms: [jwe.alg] },
        },
      }
    : { jwe: { encryptOptions: { protectedHeader } } };
  if (onKeyLookup) {
    sealing.hooks = {
      onKeyLookup: ({ header, event }) =>
        onKeyLookup(event === undefined ? { header } : { header, event }),
    };
  }
  return sealing;
}

/** `key` once it is a key unjwt can seal sign-in tokens with; `ERR_UNAUTH_CONFIG_INVALID` otherwise. */
function assertFlowKey(key: unknown): FlowKey {
  if (key === undefined || key === null) {
    throw configError(
      "The sign-in needs a flow key: give it a `key` (a symmetric JWE key, or a callback returning one).",
    );
  }
  if (typeof key === "string") {
    throw configError(
      "The sign-in `key` must be a symmetric JWE key, not a string: turn a random secret into one with `deriveJWK(secret, { info })`.",
    );
  }
  if (isFlowSecret(key)) return key;
  if (!isRecord(key) || !("keys" in key)) {
    throw configError(
      "The sign-in `key` must be symmetric (an `oct` JWK, such as `deriveJWK`'s, or a secret `CryptoKey`): a key pair seals with its public half, which anyone holding it could use to forge sign-in tokens.",
    );
  }
  if (!isFlowKeySet(key)) {
    throw configError("The sign-in `key`'s JWK Set must list one or more `oct` JWKs.");
  }
  return key;
}

function isFlowSecret(key: unknown): key is CryptoKey | FlowOctJwk {
  return (isCryptoKey(key) && key.type === "secret") || isOctJwk(key);
}

function isFlowKeySet(key: Record<string, unknown>): key is JWKSet<FlowOctJwk[]> {
  const { keys } = key;
  return Array.isArray(keys) && keys.length > 0 && keys.every(isOctJwk);
}

function namesAlgorithm(key: unknown): boolean {
  return isRecord(key) && typeof key.alg === "string";
}

type FlowOctJwk = Exclude<FlowKey, CryptoKey | JWKSet>;

function isCryptoKey(key: unknown): key is CryptoKey {
  return typeof CryptoKey !== "undefined" && key instanceof CryptoKey;
}

function isOctJwk(key: unknown): key is FlowOctJwk {
  return isRecord(key) && key.kty === "oct" && typeof key.k === "string";
}
