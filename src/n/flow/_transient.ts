import { type ExpiresIn, type SessionConfigJWE, defineJWESession } from "unjwt/session";
import { durationSeconds } from "./_http.ts";
import { createState } from "./random.ts";
import type { FlowRecord, Provider, FlowStore } from "./types.ts";

/** Where a flow record waits between the two legs. */
export interface FlowCarrierOptions {
  /** Seals the flow cookie. */
  key: SessionConfigJWE["key"];
  /** Keep records here; the cookie then carries only their id. */
  store?: FlowStore;
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

/** Writes the flow cookie (and the store's record) onto `headers`. */
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
  let cookie: FlowCookie = { record };
  if (options.store) {
    const ref = createState();
    await options.store.put(ref, record, { ttl: flowMaxAge(options) });
    cookie = { ref };
  }
  const session = await flowSession(context).use({ req: request, res: { headers } });
  if (session.id !== undefined) await session.clear();
  await session.update(cookie);
}

/** Why a callback carries no flow: no cookie at all, one that is expired or does not open, or a store record already taken. */
export type MissingFlowReason = "missing" | "unreadable" | "consumed";

/**
 * The flow record the request carries, consumed: the cookie is expired on `headers` and the
 * store's record taken, whether or not the callback goes on to succeed. Without a record, the
 * reason there is none.
 */
export async function takeFlow(context: {
  request: Request;
  headers: Headers;
  provider: Provider<unknown>;
  options: FlowCarrierOptions;
}): Promise<{ record: FlowRecord } | { record?: undefined; reason: MissingFlowReason }> {
  const { request, headers, options } = context;
  const definition = flowSession(context);
  const event = { req: request, res: { headers } };
  const present = definition.token(event) !== undefined;
  if (!present) return { reason: "missing" };
  const session = await definition.use(event);
  const { record, ref } = session.id === undefined ? {} : session.data;
  await session.clear();
  if (record) return { record };
  if (ref !== undefined && options.store) {
    const stored = await options.store.take(ref);
    return stored ? { record: stored } : { reason: "consumed" };
  }
  return { reason: "unreadable" };
}

function flowSession(context: { provider: Provider<unknown>; options: FlowCarrierOptions }) {
  const secure = context.options.cookie?.secure !== false;
  // A form_post callback is a cross-site POST: a Lax cookie would not come back with it.
  const sameSite = secure && context.provider.responseMode === "form_post" ? "none" : "lax";
  const config: SessionConfigJWE<FlowCookie, ExpiresIn> = {
    key: context.options.key,
    name: secure ? "__Host-unauth-flow" : "unauth-flow",
    maxAge: flowMaxAge(context.options),
    sessionHeader: false,
    cookie: { httpOnly: true, secure, sameSite, path: "/" },
    jwe: { encryptOptions: { protectedHeader: { typ: FLOW_TYP } } },
  };
  return defineJWESession(config);
}

/** The flow cookie's `typ`: never a session or handoff token, whatever key they share. */
const FLOW_TYP = "unauth-flow+jwt";

function flowMaxAge(options: FlowCarrierOptions): number {
  return durationSeconds(options.maxAge ?? "10m", { label: "A sign-in flow" });
}
