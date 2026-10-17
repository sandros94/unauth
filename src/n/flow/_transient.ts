import { type ExpiresIn, type SessionConfigJWE, defineJWESession } from "unjwt/session";
import { durationSeconds } from "./_http.ts";
import { createState } from "./random.ts";
import type { FlowRecord, Provider, TransientStore } from "./types.ts";

/** Where a flow record waits between the two legs. */
export interface FlowCarrierOptions {
  /** Seals the flow cookie. */
  key: SessionConfigJWE["key"];
  /** Keep records here; the cookie then carries only their id. */
  store?: TransientStore;
  cookie?: { /** @default true */ secure?: boolean };
  /**
   * How long a sign-in may take between `authorize` and `callback` (seconds, or `"10m"`…): the
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
  const session = await flowSession(context).use({ request, headers });
  if (session.id !== undefined) await session.clear();
  await session.update(cookie);
}

/**
 * The flow record the request carries, consumed: the cookie is expired on `headers` and the
 * store's record taken, whether or not the callback goes on to succeed. `undefined` when there is
 * none, it expired, or it does not open.
 */
export async function takeFlow(context: {
  request: Request;
  headers: Headers;
  provider: Provider<unknown>;
  options: FlowCarrierOptions;
}): Promise<FlowRecord | undefined> {
  const { request, headers, options } = context;
  const definition = flowSession(context);
  const present = definition.token({ request, headers }) !== undefined;
  const session = await definition.use({ request, headers });
  const { record, ref } = session.id === undefined ? {} : session.data;
  if (present) await session.clear();
  if (record) return record;
  return ref !== undefined && options.store ? options.store.take(ref) : undefined;
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
  };
  return defineJWESession(config);
}

function flowMaxAge(options: FlowCarrierOptions): number {
  return durationSeconds(options.maxAge ?? "10m", { label: "A sign-in flow" });
}
