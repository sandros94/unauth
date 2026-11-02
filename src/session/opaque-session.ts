import {
  type CookieAttributes,
  type ExpiresIn,
  type SessionDriver,
  type SessionSource,
  type WebSessionEvent,
  assertSessionConfig,
  sessionTransportOptions,
  webSessionDriver,
} from "unjwt/session";
import type { CacheDriver } from "../_internal/cache-driver.ts";
import { configError, durationSeconds } from "../_internal/shared.ts";
import type { UnauthError } from "../error.ts";
import { MAX_TOKEN_BYTES, createOpaqueToken, hashOpaqueToken } from "../token/opaque-token.ts";
import { type OpaqueContext, bindSession, isTokenShaped, loadBinding } from "./_internal/bind.ts";
import { tokenError, unjwtRethrown } from "./_internal/errors.ts";
import { manageSession } from "./_internal/manager.ts";
import { recordStore } from "./_internal/record.ts";

/** What the store holds under a token's hash. Times are ms since the epoch. */
export interface OpaqueSessionRecord<TData> {
  /** When the session was created, or last rotated. */
  createdAt: number;
  /** When the record was last written: created, updated, rotated or extended. */
  updatedAt: number;
  /** When the session ends: `maxAge` after `updatedAt`. */
  expiresAt: number;
  data: TData;
}

/** Options of {@link defineOpaqueSession}. */
export interface OpaqueSessionConfig {
  /**
   * Where records live, keyed by `prefix` and the token's {@link hashOpaqueToken} hash, never the
   * token: a table, a KV namespace, an ocache storage. `get` of a miss returns `null`;
   * `set(key, null)` removes; `set` gets a `ttl` hint, in seconds, until the record's `expiresAt`.
   * A record that fails its checks on read is removed and counts as a miss. A store that throws
   * fails the call, and every later `use()` of the same request. `maxEntryBytes` and `binary` are
   * ignored. A store of several tiers removes a session from all of them. A store that indexes
   * sessions by user reads `value.data` in `set`. A record whose response was lost (the cookie
   * never reached the client, a bearer never sent) names a token nobody holds, until its ttl.
   */
  store: CacheDriver;
  /**
   * Session lifetime after its last write: seconds, or a duration such as `"7d"`. Every write
   * (`update()`, `rotate()`, a roll) ends the session `maxAge` from then; the cookie expires with
   * it.
   */
  maxAge: ExpiresIn;
  /**
   * Makes a read a write once the session is old enough: a session read from its cookie is
   * extended to a fresh `maxAge` on every read with `true`, or once a duration (shorter than
   * `maxAge`) has passed since `updatedAt`. A read that cannot write the cookie does not extend.
   * A session read from the session header or from a token in hand never extends on a read.
   * @default undefined (a session ends `maxAge` after its last write)
   */
  rolling?: true | ExpiresIn;
  /**
   * Cookie name, also the base of the default session header `x-unauth-session`. `__Host-` and
   * `__Secure-` names get their prefix rules checked. One name is one session per request: two
   * definitions sharing it share the first one's state. @default "__Host-unauth"
   */
  name?: string;
  /**
   * Request header to read a bare or `Bearer` token from: a header name, `true` for
   * `x-<name>-session` (without a `__Host-` or `__Secure-` prefix), or `false` for none. A request
   * that sends it is read from it alone and its cookie is left as it is, unless the header holds
   * the very token of the request's session cookie. @default undefined (no header is read)
   */
  sessionHeader?: boolean | string;
  /**
   * Cookie attributes over unjwt's `DEFAULT_SESSION_COOKIE` (`path: "/"`, `secure`, `httpOnly`,
   * `sameSite: "lax"`), or `false` for no cookie: with no `sessionHeader` either, the session
   * lives in tokens in hand alone (`issue()`, `open()`, `use({ token })`). The session sets
   * `Expires` itself.
   */
  cookie?: false | CookieAttributes;
  /** What store keys start with. @default "" */
  prefix?: string;
  /** Random bytes per token, 16 to 384. @default 32 */
  bytes?: number;
}

/** What `update()` merges: a partial, or a function of the current data returning one or `undefined`. */
export type OpaqueSessionUpdate<TData> =
  | Partial<TData>
  | ((data: TData) => Partial<TData> | undefined);

/**
 * The session of one request, one object for the whole request: its getters read the current
 * state, which `update()`, `rotate()` and `clear()` change in place. Read `id` to tell a session
 * from none; `data` is `{}` without one, as unjwt's and h3's managers have it.
 */
export interface OpaqueSessionManager<TData extends object> {
  /** The token's hash, the store key; `undefined` without a session. Never the token. */
  readonly id: string | undefined;
  /**
   * The token behind this session: the one the request carried, or the last one issued on it.
   * `undefined` without a session. On a `"cookie"` session it is also in the cookie; on a
   * `"header"` or `"token"` session it is here alone, for the caller to send.
   */
  readonly token: string | undefined;
  /** When the session was created or last rotated, in ms; now without a session. */
  readonly createdAt: number;
  /** When the record was last written, in ms; now without a session. Expiry counts from it. */
  readonly updatedAt: number;
  /** When the session ends, in ms: `maxAge` after `updatedAt`. */
  readonly expiresAt: number;
  /** The session's data; `{}` without a session. */
  readonly data: TData;
  /**
   * Where this request's token comes from, decided before it is read: `"cookie"`, `"header"` or
   * `"token"` (a token in hand). A `"cookie"` session writes its cookie on every change and expires
   * it on `clear()`. A `"header"` or `"token"` session writes the store alone: a change is visible
   * to the bearer on its next request, a `clear()` revokes it, and a token `update()` or `rotate()`
   * issues is on `token` for the caller to send.
   */
  readonly source: SessionSource;
  /**
   * `ERR_SESSION_TOKEN_INVALID` when the request carries a token that names no live session (its
   * `cause.reason`: `unknown`, `expired`, or `header` for a session header without a token);
   * `undefined` when the request carries none, when the read succeeded, and after `update()` or
   * `clear()`.
   */
  readonly error: UnauthError<"ERR_SESSION_TOKEN_INVALID"> | undefined;
  /**
   * Merges `update` into the data and rewrites the record: the token stays, `updatedAt` is now
   * and the session ends `maxAge` from now; with no `update`, it only extends. Without a session
   * it creates one for `update` as the whole data: a new token (in the cookie, or on `token`), a
   * record that ends `maxAge` from now. At sign-in, `clear()` first, so the signed-in session gets
   * a token nobody held before.
   * @throws `ERR_SESSION_READONLY_EVENT` if a `"cookie"` session has no response, or it was sent.
   * @throws `TypeError` if `update` is not a plain object, or a function returning one or `undefined`.
   */
  update(update?: OpaqueSessionUpdate<TData>): Promise<this>;
  /**
   * Moves the session under a new token: the old one names nothing from now on, `createdAt` and
   * `updatedAt` are now, the session ends `maxAge` from now, the data stays. Tracking which token
   * a session had before is the application's.
   * @throws `ERR_SESSION_READONLY_EVENT` if a `"cookie"` session has no response, or it was sent.
   * @throws `TypeError` without a session.
   */
  rotate(): Promise<this>;
  /**
   * Removes the record and, on a `"cookie"` session, expires the cookie: the session is empty for
   * the rest of the request, and the token the client holds names nothing.
   * @throws `ERR_SESSION_READONLY_EVENT` once the response was sent.
   */
  clear(): Promise<this>;
}

/** What `open()` reads from a token. */
export interface OpaqueSessionOpened<TData> extends OpaqueSessionRecord<TData> {
  id: string;
  token: string;
  source: "token";
}

/** One opaque session, defined once and used on any request. */
export interface OpaqueSessionDefinition<TData extends object, TEvent = WebSessionEvent> {
  /**
   * Reads the request's session. Later calls on the same request return the same manager.
   * @throws `ERR_UNAUTH_CONFIG_INVALID` if a session of another kind uses the name on this request,
   * the event is not one the driver takes, or a request event has no token source to read
   * (`cookie: false` without `sessionHeader`).
   * @throws whatever the store throws.
   */
  use(event: TEvent): Promise<OpaqueSessionManager<TData>>;
  /**
   * The transport's token, unread: the one the request carries (a token in hand, the session
   * header, else the cookie) whatever `use()` made of it, or the one `update()` or `rotate()`
   * issued on this request. `undefined` when the request carries none, and after `clear()`.
   */
  token(event: TEvent): string | undefined;
  /** A token for a new session over `data`, ending `maxAge` from now. Reads and writes no request. */
  issue(data: TData): Promise<string>;
  /**
   * The session a token names, from the store.
   * @throws `ERR_SESSION_TOKEN_INVALID` if the token names no live session.
   */
  open(token: string): Promise<OpaqueSessionOpened<TData>>;
}

/**
 * Defines a server-side session: the cookie (or the session header) carries a random token, the
 * store its hash and the data. Its manager speaks `defineJWESession`'s vocabulary (`id`, `data`,
 * `update()`, `clear()`, `source`, `error`), with `rotate()` on top; pick this one to list or
 * revoke sessions from the store.
 *
 * @throws `ERR_UNAUTH_CONFIG_INVALID` for a `maxAge` or `rolling` that is not a positive duration,
 * a `rolling` not shorter than `maxAge`, a `name`, `sessionHeader` or `cookie` the cookie rules
 * refuse, or `bytes` outside 16 to 384.
 *
 * @example
 * const sessions = defineOpaqueSession<{ userId: string }>({ store, maxAge: "7d", rolling: "1d" });
 * const session = await sessions.use(event);
 * await session.clear();
 * await session.update({ userId: user.id });
 */
export function defineOpaqueSession<TData extends object>(
  config: OpaqueSessionConfig,
): OpaqueSessionDefinition<TData>;
/** The same session over a framework's own driver (`defineSessionDriver`), for its event type. */
export function defineOpaqueSession<TData extends object, TEvent>(
  config: OpaqueSessionConfig,
  options: { driver: SessionDriver<TEvent> },
): OpaqueSessionDefinition<TData, TEvent>;
export function defineOpaqueSession<TData extends object, TEvent>(
  config: OpaqueSessionConfig,
  options?: { driver?: SessionDriver<TEvent> },
): OpaqueSessionDefinition<TData, TEvent> {
  const driver = options?.driver ?? defaultDriver<TEvent>();
  const { prefix } = driver;
  const name = config.name ?? DEFAULT_NAME;
  unjwtRethrown(() => assertSessionConfig(config, { name, prefix }));
  const maxAge = durationSeconds(config.maxAge, { label: "A session", prefix }) * 1000;
  const rolling =
    config.rolling === undefined
      ? undefined
      : config.rolling === true
        ? 0
        : durationSeconds(config.rolling, { label: 'A session\'s "rolling"', prefix }) * 1000;
  const bytes = config.bytes ?? 32;
  if (!Number.isInteger(bytes) || bytes < 16 || bytes > MAX_TOKEN_BYTES) {
    throw configError(
      `A session token needs a whole number of 16 to ${MAX_TOKEN_BYTES} random bytes, got ${bytes}.`,
      { prefix },
    );
  }
  const context: OpaqueContext<TData> = {
    name,
    prefix,
    bytes,
    maxAge,
    rolling,
    now,
    records: recordStore<TData>(config.store, { prefix: config.prefix ?? "", now }),
    transport: sessionTransportOptions(config, { name }),
  };

  return {
    use: async (event) => {
      const binding = bindSession(driver, event, context);
      await loadBinding(binding, context);
      return (binding.manager ||= manageSession(binding, context));
    },
    token: (event) => {
      const binding = bindSession(driver, event, context);
      if (binding.cleared) return undefined;
      return binding.issued ?? binding.held ?? binding.transport.read?.();
    },
    issue: async (data) => {
      const { token, hash } = await createOpaqueToken({ bytes });
      const at = now();
      await context.records.write(hash, {
        createdAt: at,
        updatedAt: at,
        expiresAt: at + maxAge,
        data,
      });
      return token;
    },
    open: async (token) => {
      const id = isTokenShaped(token) ? await hashOpaqueToken(token) : undefined;
      const found = id === undefined ? undefined : await context.records.read(id);
      if (id === undefined || !found?.record) {
        throw tokenError(prefix, { reason: found?.reason ?? "unknown" });
      }
      return { ...found.record, id, token, source: "token" };
    },
  };
}

const PREFIX = "[unauth/session]";

/** The clock, read at each call so a test may replace `Date`. */
const now = (): number => Date.now();

const DEFAULT_NAME = "__Host-unauth";

/** The Web driver; without a driver, the first overload fixes the event to a Web one. */
function defaultDriver<TEvent>(): SessionDriver<TEvent> {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- `TEvent` is `WebSessionEvent` whenever no driver is given
  return webSessionDriver({ prefix: PREFIX }) as SessionDriver<TEvent>;
}
