import {
  type SessionDriver,
  type SessionTransport,
  type SessionTransportOptions,
  assertSessionTokenSource,
  assertSessionWritable,
  claimSessionName,
  resolveSessionTransport,
} from "unjwt/session";
import { isRecord } from "../../_internal/shared.ts";
import type { UnauthError } from "../../error.ts";
import { createOpaqueToken } from "../../token/opaque-token.ts";
import type { OpaqueSession, OpaqueSessionNone, OpaqueSessionUpdate } from "../opaque-session.ts";
import type { OpaqueSessionRecord, OpaqueSessionStore } from "../opaque-store.ts";
import { configError } from "../../_internal/shared.ts";
import { noSessionError, tokenError, unjwtRethrown } from "./errors.ts";
import {
  type Lifetimes,
  absoluteEndOf,
  endOf,
  hasEnded,
  isDueForTouch,
  timesAt,
} from "./lifecycle.ts";

/** What one definition decided once, for every request. */
export interface OpaqueSettings extends Lifetimes {
  name: string;
  prefix: string;
  bytes: number;
  generateId: () => string;
  transport: SessionTransportOptions;
  now: () => number;
}

/** The settings plus the store as seen from a request event (or from none). */
export interface OpaqueContext<TData extends object, TEvent> extends OpaqueSettings {
  store: (event?: TEvent) => OpaqueSessionStore<TData>;
}

/** One session bound to one request; what `use()` returns is a view over it. */
interface Binding<TData extends object> {
  transport: SessionTransport;
  store: () => OpaqueSessionStore<TData>;
  /** The token the request carried, as read. */
  held: string | undefined;
  /** The token `update()` or `rotate()` issued on this request. */
  issued: string | undefined;
  cleared: boolean;
  /** The one store read, once started. */
  loaded: Promise<OpaqueSessionRecord<TData> | undefined> | undefined;
  record: OpaqueSessionRecord<TData> | undefined;
  error: UnauthError<"ERR_SESSION_TOKEN_INVALID"> | undefined;
  session: OpaqueSession<TData> | undefined;
}

/** What `record` resolves to without a session. */
const NONE: OpaqueSessionNone = Object.freeze({
  id: undefined,
  createdAt: undefined,
  updatedAt: undefined,
  expiresAt: undefined,
  data: undefined,
});

/** The bindings of one request, by session name, in a slot of the driver's state record. */
const kOpaqueSessions: unique symbol = Symbol("unauth_opaque_sessions");

/**
 * The request's session, claimed under its name on the first call, the same object after. No
 * store call happens here: the token is read from the request, nothing else.
 * @throws `ERR_UNAUTH_CONFIG_INVALID` if another kind of session uses the name on this request, the
 * event is not one the driver takes, or a request event has no token source.
 */
export function bindSession<TData extends object, TEvent>(
  driver: SessionDriver<TEvent>,
  event: TEvent,
  context: OpaqueContext<TData, TEvent>,
): OpaqueSession<TData> {
  const { name, prefix } = context;
  const holder: { [kOpaqueSessions]?: Map<string, Binding<TData>> } = unjwtRethrown(() =>
    driver.state(event),
  );
  unjwtRethrown(() => claimSessionName(holder, { name, family: "opaque", prefix }));
  const bindings = (holder[kOpaqueSessions] ||= new Map());
  let binding = bindings.get(name);
  if (!binding) {
    const transport = unjwtRethrown(() =>
      resolveSessionTransport(driver, event, context.transport),
    );
    unjwtRethrown(() => assertSessionTokenSource(transport, { prefix }));
    binding = {
      transport,
      store: () => context.store(event),
      held: transport.malformed ? undefined : transport.read?.(),
      issued: undefined,
      cleared: false,
      loaded: undefined,
      record: undefined,
      error: transport.malformed
        ? tokenError(prefix, { reason: "header", header: transport.malformed.header })
        : undefined,
      session: undefined,
    };
    bindings.set(name, binding);
  }
  return (binding.session ||= sessionOf(binding, context));
}

function sessionOf<TData extends object>(
  binding: Binding<TData>,
  settings: OpaqueSettings,
): OpaqueSession<TData> {
  const { transport } = binding;
  const { prefix } = settings;
  const token = () => (binding.cleared ? undefined : (binding.issued ?? binding.held));
  const writable = (operation: "update" | "clear") =>
    unjwtRethrown(() => assertSessionWritable(transport, { operation, prefix }));
  const settle = (record: OpaqueSessionRecord<TData> | undefined) => {
    binding.record = record;
    binding.loaded = Promise.resolve(record);
    binding.error = undefined;
  };
  const deliver = (next: string, record: OpaqueSessionRecord<TData>) => {
    transport.write?.(next, { expiresAt: absoluteEndOf(settings, record.createdAt) });
    binding.issued = next;
    binding.cleared = false;
  };

  const load = (): Promise<OpaqueSessionRecord<TData> | undefined> => (binding.loaded ||= read());

  async function read(): Promise<OpaqueSessionRecord<TData> | undefined> {
    const carried = token();
    if (carried === undefined) return undefined;
    const store = binding.store();
    const found = await store.find(carried);
    const now = settings.now();
    if (!found) {
      binding.error = tokenError(prefix, { reason: "unknown" });
      return undefined;
    }
    if (hasEnded(found, now)) {
      binding.error = tokenError(prefix, { reason: "expired" });
      if (transport.writable()) transport.drop?.();
      return undefined;
    }
    if (!isDueForTouch(found, settings, now)) return (binding.record = found);
    const times = timesAt(found, settings, now);
    if (!(await store.touch(carried, times))) {
      binding.error = tokenError(prefix, { reason: "unknown" });
      return undefined;
    }
    return (binding.record = { ...found, ...times });
  }

  return {
    get token() {
      return token();
    },
    get source() {
      return transport.source;
    },
    get error() {
      return binding.error;
    },
    get record() {
      return load().then((record) => record ?? NONE);
    },
    update: async (update: OpaqueSessionUpdate<TData>) => {
      writable("update");
      const current = await load();
      const patch = typeof update === "function" ? update(current?.data) : update;
      if (patch !== undefined && !isRecord(patch)) {
        throw new TypeError(`${prefix} A session update must be a plain object.`);
      }
      const now = settings.now();
      const carried = token();
      if (current && carried !== undefined) {
        const record = {
          ...current,
          ...timesAt(current, settings, now),
          data: { ...current.data, ...patch },
        };
        await binding.store().save(carried, record);
        settle(record);
        return record;
      }
      if (!patch || Object.keys(patch).length === 0) return undefined;
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- a session is created from its whole data: the first `update()` carries it, as `OpaqueSession.update` documents
      const data = patch as TData;
      const { token: next } = await createOpaqueToken({ bytes: settings.bytes });
      const record: OpaqueSessionRecord<TData> = {
        id: mintId(settings),
        createdAt: now,
        updatedAt: now,
        expiresAt: endOf(settings, { createdAt: now, now }),
        data,
      };
      await binding.store().save(next, record);
      settle(record);
      deliver(next, record);
      return record;
    },
    rotate: async () => {
      writable("update");
      const carried = token();
      const current = await load();
      if (carried === undefined || !current) throw noSessionError(prefix);
      const { token: next } = await createOpaqueToken({ bytes: settings.bytes });
      const times = timesAt(current, settings, settings.now());
      if (!(await binding.store().rekey(carried, next, times))) {
        settle(undefined);
        throw noSessionError(prefix);
      }
      const record = { ...current, ...times };
      settle(record);
      deliver(next, record);
      return record;
    },
    clear: async () => {
      writable("clear");
      const carried = token();
      if (carried !== undefined) await binding.store().delete(carried);
      transport.drop?.();
      binding.issued = undefined;
      binding.cleared = true;
      settle(undefined);
      return NONE;
    },
  };
}

/** A new session id from the config's generator; an empty one is a config error. */
export function mintId(settings: Pick<OpaqueSettings, "generateId" | "prefix">): string {
  const id = settings.generateId();
  if (typeof id !== "string" || id === "") {
    throw configError('A session\'s "generateId" must return a non-empty string.', {
      prefix: settings.prefix,
      cause: { id },
    });
  }
  return id;
}
