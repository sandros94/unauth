import { assertSessionWritable } from "unjwt/session";
import { isRecord } from "../../_internal/shared.ts";
import { createOpaqueToken } from "../../token/opaque-token.ts";
import type { OpaqueSessionManager, OpaqueSessionRecord } from "../opaque-session.ts";
import type { OpaqueBinding, OpaqueContext } from "./bind.ts";
import { unjwtRethrown } from "./errors.ts";

/** The manager of a loaded binding; its getters read the binding's state as it changes. */
export function manageSession<TData extends object>(
  binding: OpaqueBinding<TData>,
  context: OpaqueContext<TData>,
): OpaqueSessionManager<TData> {
  const { transport, state } = binding;
  const { prefix, records } = context;

  const writable = (operation: "update" | "clear") =>
    unjwtRethrown(() => assertSessionWritable(transport, { operation, prefix }));

  const deliver = (token: string, expiresAt: number) => {
    if (transport.write) transport.write(token, { expiresAt });
    binding.issued = token;
    binding.cleared = false;
    state.token = token;
  };

  const put = async (id: string, record: OpaqueSessionRecord<TData>) => {
    await records.write(id, record);
    state.id = id;
    state.record = record;
    state.error = undefined;
  };

  const manager: OpaqueSessionManager<TData> = {
    get id() {
      return state.id;
    },
    get token() {
      return state.token;
    },
    get createdAt() {
      return state.record.createdAt;
    },
    get updatedAt() {
      return state.record.updatedAt;
    },
    get expiresAt() {
      return state.record.expiresAt;
    },
    get data() {
      return state.record.data;
    },
    get source() {
      return transport.source;
    },
    get error() {
      return state.error;
    },
    update: async (update) => {
      writable("update");
      const patch = typeof update === "function" ? update(state.record.data) : update;
      if (patch !== undefined && !isRecord(patch)) {
        throw new TypeError(`${prefix} A session update must be a plain object.`);
      }
      const now = context.now();
      const data = { ...state.record.data, ...patch };
      if (state.id !== undefined && state.token !== undefined) {
        await put(state.id, { ...state.record, updatedAt: now, data });
        deliver(state.token, state.record.expiresAt);
        return manager;
      }
      const { token, hash } = await createOpaqueToken({ bytes: context.bytes });
      await put(hash, { createdAt: now, updatedAt: now, expiresAt: now + context.maxAge, data });
      deliver(token, now + context.maxAge);
      return manager;
    },
    rotate: async () => {
      writable("update");
      const { id, record } = state;
      if (id === undefined) throw new TypeError(`${prefix} There is no session to rotate.`);
      const { token, hash } = await createOpaqueToken({ bytes: context.bytes });
      await records.remove(id);
      state.id = undefined;
      state.token = undefined;
      const now = context.now();
      await put(hash, { ...record, createdAt: now, updatedAt: now });
      deliver(token, record.expiresAt);
      return manager;
    },
    clear: async () => {
      writable("clear");
      if (state.id !== undefined) await records.remove(state.id);
      transport.drop?.();
      binding.issued = undefined;
      binding.cleared = true;
      state.id = undefined;
      state.token = undefined;
      state.record = blankRecord(context);
      state.error = undefined;
      return manager;
    },
  };
  return manager;
}

/** The record of no session: created now, ending `maxAge` from now, no data. */
export function blankRecord<TData extends object>(
  context: OpaqueContext<TData>,
): OpaqueSessionRecord<TData> {
  const now = context.now();
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- no session has no data: `{}`, as unjwt's and h3's managers have it
  return { createdAt: now, updatedAt: now, expiresAt: now + context.maxAge, data: {} as TData };
}
