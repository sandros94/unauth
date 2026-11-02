import {
  type SessionDriver,
  type SessionTransport,
  type SessionTransportOptions,
  assertSessionTokenSource,
  claimSessionName,
  resolveSessionTransport,
} from "unjwt/session";
import type { UnauthError } from "../../error.ts";
import { hashOpaqueToken } from "../../token/opaque-token.ts";
import type { OpaqueSessionManager, OpaqueSessionRecord } from "../opaque-session.ts";
import { tokenError, unjwtRethrown } from "./errors.ts";
import { blankRecord } from "./manager.ts";
import type { RecordStore } from "./record.ts";

/** What one definition shares across requests. */
export interface OpaqueContext<TData extends object> {
  name: string;
  prefix: string;
  bytes: number;
  maxAge: number;
  rolling: number | undefined;
  records: RecordStore<TData>;
  transport: SessionTransportOptions;
  now: () => number;
}

/** The session state of one request; without a session, `record` is the blank one. */
export interface OpaqueState<TData extends object> {
  id: string | undefined;
  token: string | undefined;
  record: OpaqueSessionRecord<TData>;
  error: UnauthError<"ERR_SESSION_TOKEN_INVALID"> | undefined;
}

/**
 * One session bound to one request: its transport, its read (once), the token the request carried
 * as read (`held`), the one issued on it, and whether it was cleared.
 */
export interface OpaqueBinding<TData extends object> {
  transport: SessionTransport;
  state: OpaqueState<TData>;
  loaded?: Promise<void>;
  manager?: OpaqueSessionManager<TData>;
  held: string | undefined;
  issued: string | undefined;
  cleared: boolean;
}

/** The bindings of one request, by session name, in a slot of the driver's state record. */
const kOpaqueSessions: unique symbol = Symbol("unauth_opaque_sessions");

/**
 * The request's binding for this session, claimed under its name on the first call. The token is
 * not read until {@link loadBinding}.
 * @throws `ERR_UNAUTH_CONFIG_INVALID` if another kind of session uses the name on this request, or
 * the event is not one the driver takes.
 */
export function bindSession<TData extends object, TEvent>(
  driver: SessionDriver<TEvent>,
  event: TEvent,
  context: OpaqueContext<TData>,
): OpaqueBinding<TData> {
  const { name, prefix } = context;
  const holder: { [kOpaqueSessions]?: Map<string, OpaqueBinding<TData>> } = unjwtRethrown(() =>
    driver.state(event),
  );
  unjwtRethrown(() => claimSessionName(holder, { name, family: "opaque", prefix }));
  const bindings = (holder[kOpaqueSessions] ||= new Map());
  let binding = bindings.get(name);
  if (!binding) {
    binding = {
      transport: unjwtRethrown(() => resolveSessionTransport(driver, event, context.transport)),
      state: { id: undefined, token: undefined, record: blankRecord(context), error: undefined },
      held: undefined,
      issued: undefined,
      cleared: false,
    };
    bindings.set(name, binding);
  }
  return binding;
}

/** Reads the request's token into the binding's state, once; later calls share the read, a failed one included. */
export function loadBinding<TData extends object>(
  binding: OpaqueBinding<TData>,
  context: OpaqueContext<TData>,
): Promise<void> {
  return (binding.loaded ||= read(binding, context));
}

/** Whether a token has the shape {@link hashOpaqueToken} is worth running on. */
export function isTokenShaped(token: string): boolean {
  return TOKEN.test(token);
}

const TOKEN = /^[\w-]{22,512}$/;

async function read<TData extends object>(
  binding: OpaqueBinding<TData>,
  context: OpaqueContext<TData>,
): Promise<void> {
  const { transport, state } = binding;
  const { prefix, records } = context;
  unjwtRethrown(() => assertSessionTokenSource(transport, { prefix }));
  if (transport.malformed) {
    state.error = tokenError(prefix, { reason: "header", header: transport.malformed.header });
    return;
  }
  const token = transport.read?.();
  if (!token) return;
  binding.held = token;
  const id = isTokenShaped(token) ? await hashOpaqueToken(token) : undefined;
  const found = id === undefined ? undefined : await records.read(id);
  if (id === undefined || !found?.record) {
    state.error = tokenError(prefix, { reason: found?.reason ?? "unknown" });
    transport.drop?.();
    return;
  }
  state.id = id;
  state.token = token;
  state.record = found.record;
  await roll(binding, context);
}

/** Extends a cookie session read past its `rolling` point to a fresh `maxAge`, cookie included. */
async function roll<TData extends object>(
  binding: OpaqueBinding<TData>,
  context: OpaqueContext<TData>,
): Promise<void> {
  const { rolling, maxAge, records } = context;
  const { transport, state } = binding;
  if (rolling === undefined || !transport.write || !transport.writable()) return;
  if (state.id === undefined || state.token === undefined) return;
  const now = context.now();
  if (now - (state.record.expiresAt - maxAge) < rolling) return;
  const record = { ...state.record, updatedAt: now, expiresAt: now + maxAge };
  await records.write(state.id, record);
  transport.write(state.token, { expiresAt: record.expiresAt });
  state.record = record;
}
