import { type ExpiresIn, type SessionConfigJWE, defineJWESession } from "unjwt/session";
import {
  type FlowEvent,
  type FlowKey,
  type FlowKeyAlgorithms,
  type FlowKeyLookup,
  flowSessionOptions,
} from "../../../_internal/flow-key.ts";
import { definedSession, keyLookupFailure } from "../../../../_internal/session-error.ts";
import { durationSeconds } from "../http/shared.ts";
import { createState } from "../../random.ts";
import type { FlowRecord, Provider, FlowStore } from "../../types.ts";

/** Where a flow record waits between the two legs. */
export interface FlowCarrierOptions {
  /**
   * Seals the flow cookie, and a relocated sign-in's intent and handoff: an `oct` JWK
   * (`deriveJWK`'s, the suggested key), a secret `CryptoKey`, or a JWK Set of `oct` JWKs whose
   * first key seals and every key opens, so the flow cookies, intents and handoffs sealed before a
   * rotation that put a new key first still open. A key naming no `alg` needs `jwe`.
   */
  key: FlowKey;
  /**
   * The JWE `alg` and `enc` the key seals with: required when a key names no algorithm (a
   * `CryptoKey`, an `oct` JWK without `alg`, a JWK Set entry without one). Such a key, and one
   * `onKeyLookup` returns, opens tokens sealed under this `alg`.
   */
  jwe?: FlowKeyAlgorithms;
  /**
   * Picks the key that opens a flow cookie, intent or handoff from its protected header (its
   * `kid`), and a flow cookie's from the request it comes with, for keys kept elsewhere (a KMS, a
   * remote JWK Set): it replaces `key` for opening, while `key` still seals. A key it returns
   * naming no `alg` opens tokens sealed under `jwe.alg`. What it throws propagates as it is;
   * `undefined` refuses the token as one that does not open: `ERR_AUTHN_FLOW_EXPIRED`. See
   * {@link FlowKeyLookup}.
   */
  onKeyLookup?: FlowKeyLookup;
  /**
   * Keep records here; the cookie then carries only their id. `take` is the store's single-use
   * guarantee, so a callback takes the record before its `state` is compared: a stray callback
   * ends a store-backed sign-in. Without a store, a callback whose `state` does not match leaves
   * the flow cookie, and the sign-in, alive.
   */
  store?: FlowStore;
  /** The framework's per-request state, as the event carries it; handed to the flow session as is. */
  context?: Record<string, unknown>;
  /** Flow cookie attributes; `secure: false` names the cookie `unauth-flow`, without the `__Host-` prefix. */
  cookie?: { /** @default true */ secure?: boolean };
  /**
   * How long a sign-in may take between `startFlow` and `completeFlow` (seconds, or `"10m"`…): the
   * flow cookie's lifetime and the store's `ttl`. Give both legs the same value.
   *
   * @default "10m"
   */
  maxAge?: ExpiresIn;
}

interface FlowCookie {
  record?: FlowRecord;
  ref?: string;
}

/**
 * Writes the flow cookie (and the store's record) onto `headers`, replacing the one the request
 * carries; what `onKeyLookup` throws reading that one propagates as it is.
 */
export async function saveFlow(
  record: FlowRecord,
  context: {
    request: Request;
    headers: Headers;
    provider: Provider<unknown>;
    options: FlowCarrierOptions;
  },
): Promise<void> {
  const { options, request, headers } = context;
  const session = await flowSession(context).use(eventOf(request, headers, options));
  const failure = keyLookupFailure(session.error);
  if (failure) throw failure.error;
  let cookie: FlowCookie = { record };
  if (options.store) {
    const ref = createState();
    await options.store.put(ref, record, { ttl: flowMaxAge(options) });
    cookie = { ref };
  }
  if (session.id !== undefined) await session.clear();
  await session.update(cookie);
}

/** Why a callback carries no flow: no cookie at all, one that is expired or does not open, or a store record already taken. */
export type MissingFlowReason = "missing" | "unreadable" | "consumed";

/** The flow a request carries, with `consume` to end it once the callback is known to belong to it; else why there is none. */
export type OpenedFlow =
  | { record: FlowRecord; consume: () => Promise<void> }
  | { record?: undefined; reason: MissingFlowReason };

/**
 * The flow record the request carries. A record the cookie carries is left in place until
 * `consume` expires the cookie on `headers`; a store's record is taken here, its cookie expired,
 * and `consume` has nothing left to do. A cookie that does not open is expired too. Without a
 * record, the reason there is none. What `onKeyLookup` throws propagates as it is, the cookie left
 * in place.
 */
export async function openFlow(context: {
  request: Request;
  headers: Headers;
  provider: Provider<unknown>;
  options: FlowCarrierOptions;
}): Promise<OpenedFlow> {
  const { request, headers, options } = context;
  const definition = flowSession(context);
  const event = eventOf(request, headers, options);
  if (definition.token(event) === undefined) return { reason: "missing" };
  const session = await definition.use(event);
  const failure = keyLookupFailure(session.error);
  if (failure) throw failure.error;
  const { record, ref } = session.id === undefined ? {} : session.data;
  if (record) {
    return {
      record,
      consume: async () => {
        await session.clear();
      },
    };
  }
  await session.clear();
  if (ref !== undefined && options.store) {
    const stored = await options.store.take(ref);
    return stored ? { record: stored, consume: () => Promise.resolve() } : { reason: "consumed" };
  }
  return { reason: "unreadable" };
}

function flowSession(context: { provider: Provider<unknown>; options: FlowCarrierOptions }) {
  const secure = context.options.cookie?.secure !== false;
  // A form_post callback is a cross-site POST: a Lax cookie would not come back with it.
  const sameSite = secure && context.provider.responseMode === "form_post" ? "none" : "lax";
  const { key, jwe, onKeyLookup } = context.options;
  const config: SessionConfigJWE<FlowCookie, ExpiresIn, FlowEvent> = {
    key,
    name: secure ? "__Host-unauth-flow" : "unauth-flow",
    maxAge: flowMaxAge(context.options),
    sessionHeader: false,
    cookie: { httpOnly: true, secure, sameSite, path: "/" },
    ...flowSessionOptions(key, { typ: FLOW_TYP, jwe, onKeyLookup }),
  };
  return definedSession(() => defineJWESession<FlowCookie, ExpiresIn, FlowEvent>(config), {
    prefix: "[unauth/n]",
  });
}

/** The flow cookie's `typ`: never a session or handoff token, whatever key they share. */
const FLOW_TYP = "unauth-flow+jwt";

function flowMaxAge(options: FlowCarrierOptions): number {
  return durationSeconds(options.maxAge ?? "10m", { label: "A sign-in flow" });
}

/** The event the flow session reads: the request, the response headers, and the framework's context when there is one. */
function eventOf(request: Request, headers: Headers, options: FlowCarrierOptions): FlowEvent {
  const event: FlowEvent = { req: request, res: { headers } };
  if (options.context !== undefined) event.context = options.context;
  return event;
}
