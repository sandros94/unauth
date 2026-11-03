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
import { configError, durationSeconds } from "../_internal/shared.ts";
import type { UnauthError } from "../error.ts";
import { MAX_TOKEN_BYTES, createOpaqueToken } from "../token/opaque-token.ts";
import { type OpaqueContext, bindSession, mintId } from "./_internal/bind.ts";
import { unjwtRethrown } from "./_internal/errors.ts";
import { endOf } from "./_internal/lifecycle.ts";
import type { OpaqueSessionRecord, OpaqueSessionStore } from "./opaque-store.ts";

/** Options of {@link defineOpaqueSession}; `TEvent` is the request event a `store` factory gets. */
export interface OpaqueSessionConfig<TData, TEvent = WebSessionEvent> {
  /**
   * Where sessions live, keyed by the token the client holds (see {@link OpaqueSessionStore}), or
   * a function of the request event answering the store for it, called at every operation: the
   * client the request holds, or the transaction it opened since. `issue()` calls it without an
   * event. A record whose response was lost names a token nobody holds, until it ends.
   */
  store: OpaqueSessionStore<TData> | ((event?: TEvent) => OpaqueSessionStore<TData>);
  /**
   * Absolute lifetime: the session ends this long after it was created, whatever happens, and the
   * cookie carries that end as `Expires`. `rotate()` never restarts it. Unset, nothing but `idle`
   * ends the session and the cookie lasts the browser session. @default undefined
   */
  maxAge?: ExpiresIn;
  /**
   * Idle lifetime: the session ends this long after its last activity. A read extends it once at
   * least half of it has passed since the last write, with the store's `touch` alone: the cookie
   * is not rewritten. Unset, the session ends at `maxAge` however often it is read.
   * @default undefined
   */
  idle?: ExpiresIn;
  /**
   * Cookie name, also the base of the default session header `x-unauth-session`. `__Host-` and
   * `__Secure-` names get their prefix rules checked. One name is one session per request.
   * @default "__Host-unauth"
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
   * Cookie attributes over unjwt's `DEFAULT_SESSION_COOKIE`, or `false` for no cookie: with no
   * `sessionHeader` either, the session lives in tokens in hand alone (`issue()`, `use({ token })`).
   */
  cookie?: false | CookieAttributes;
  /** Random bytes per token, 16 to 384. @default 32 */
  bytes?: number;
  /**
   * Makes a session's `id`, the stable name a session keeps across `rotate()`; it must not be
   * empty. @default crypto.randomUUID
   */
  generateId?: () => string;
}

/**
 * What `update()` merges: a partial, or a function of the current data (`undefined` without a
 * session) returning one or `undefined`.
 */
export type OpaqueSessionUpdate<TData> =
  | Partial<TData>
  | ((data: TData | undefined) => Partial<TData> | undefined);

/** What `record` resolves to without a live session: the record's fields, all `undefined`. */
export interface OpaqueSessionNone {
  id: undefined;
  createdAt: undefined;
  updatedAt: undefined;
  expiresAt: undefined;
  data: undefined;
}

/**
 * The session of one request, one object for the whole request, shared by every `use()` on it.
 * Nothing here touches the store until `record` is read or a write is made.
 */
export interface OpaqueSession<TData extends object> {
  /**
   * The token the request carries, or the last one issued on it: what the store is asked for, not
   * checked against it. `undefined` when the request carries none, and after `clear()`. To filter
   * a query of your own on the session, hash it the way your store does.
   */
  readonly token: string | undefined;
  /**
   * Where the token comes from: `"cookie"`, `"header"` or `"token"` (a token in hand). A `"cookie"`
   * session writes its cookie when a token is issued and expires it on `clear()`; the others write
   * the store alone, the token `update()` or `rotate()` issues being on `token` for the caller to
   * send.
   */
  readonly source: SessionSource;
  /**
   * Why the request's token names no session: `ERR_SESSION_TOKEN_INVALID` with `cause.reason`
   * `header` (known before any read), `unknown` or `expired` (known once `data` was read).
   * `undefined` when the request carries no token, when the read found the session, and after a
   * write.
   */
  readonly error: UnauthError<"ERR_SESSION_TOKEN_INVALID"> | undefined;
  /**
   * The session as the store holds it, or {@link OpaqueSessionNone} without a live session: every
   * field `undefined`, so `id` tells the two apart and narrows the rest. The one store read of the
   * request, shared by every later access and write: reading extends an idle session when due, an
   * expired session expires the cookie, an unknown token leaves it for your sign-in to replace.
   */
  readonly record: Promise<OpaqueSessionRecord<TData> | OpaqueSessionNone>;
  /**
   * With a session, merges `update` into its data and writes the record: the token stays, the
   * idle clock restarts. Without one, creates a session for `update` as its whole data, with a new
   * token in the cookie (or on `token`); an empty `update` creates nothing, so a visitor who never
   * signs in never gets a record. Returns the record after, `undefined` when nothing was created.
   * @throws `ERR_SESSION_READONLY_EVENT` if a `"cookie"` session has no response, or it was sent.
   * @throws `TypeError` if `update` is not a plain object, or a function returning one or `undefined`.
   */
  update(update: OpaqueSessionUpdate<TData>): Promise<OpaqueSessionRecord<TData> | undefined>;
  /**
   * Moves the session under a new token, on `token` after: the old one names nothing from now on,
   * `id` and `createdAt` stay, the idle clock restarts, the absolute end does not move. Returns
   * the record as written.
   * @throws `ERR_SESSION_NONE` without a live session.
   * @throws `ERR_SESSION_READONLY_EVENT` if a `"cookie"` session has no response, or it was sent.
   */
  rotate(): Promise<OpaqueSessionRecord<TData>>;
  /**
   * Removes the session and, on a `"cookie"` session, expires the cookie; no read. The request has
   * no session after, and `update()` would create a new one. Returns {@link OpaqueSessionNone}.
   * @throws `ERR_SESSION_READONLY_EVENT` once the response was sent.
   */
  clear(): Promise<OpaqueSessionNone>;
}

/** One opaque session, defined once and used on any request. */
export interface OpaqueSessionDefinition<TData extends object, TEvent = WebSessionEvent> {
  /**
   * The request's session, without touching the store: the token is read from the request, the
   * rest waits for `record` or a write. Later calls on the same request return the same object.
   * @throws `ERR_UNAUTH_CONFIG_INVALID` if a session of another kind uses the name on this request,
   * the event is not one the driver takes, or a request event has no token source to read
   * (`cookie: false` without `sessionHeader`).
   */
  use(event: TEvent): OpaqueSession<TData>;
  /** A token for a new session over `data`, with the lifetimes of the config. Reads and writes no request. */
  issue(data: TData): Promise<string>;
}

/**
 * Defines a server-side session: the cookie (or the session header) carries a random token, the
 * store the session under it. Unlike `defineJWESession`'s manager, whose data travels in the
 * token, this one reads the store only when asked: `use()` is synchronous, `record` is a promise.
 *
 * @throws `ERR_UNAUTH_CONFIG_INVALID` for a `maxAge` or `idle` that is not a positive duration, a
 * `name`, `sessionHeader` or `cookie` the cookie rules refuse, `bytes` outside 16 to 384, or, when
 * a session is created, a `generateId` that returns no non-empty string.
 *
 * @example
 * const sessions = defineOpaqueSession<{ userId: string }>({ store, maxAge: "30D", idle: "7D" });
 * const session = sessions.use(event);
 * const { id, data, expiresAt } = await session.record;
 * if (!id) throw createError({ statusCode: 401 });
 * return { userId: data.userId, expiresAt };
 */
export function defineOpaqueSession<
  TData extends object,
  TEvent extends WebSessionEvent = WebSessionEvent,
>(config: OpaqueSessionConfig<TData, TEvent>): OpaqueSessionDefinition<TData, TEvent>;
/** The same session over a framework's own driver (`defineSessionDriver`), for its event type. */
export function defineOpaqueSession<TData extends object, TEvent>(
  config: OpaqueSessionConfig<TData, TEvent>,
  options: { driver: SessionDriver<TEvent> },
): OpaqueSessionDefinition<TData, TEvent>;
export function defineOpaqueSession<TData extends object, TEvent>(
  config: OpaqueSessionConfig<TData, TEvent>,
  options?: { driver?: SessionDriver<TEvent> },
): OpaqueSessionDefinition<TData, TEvent> {
  const driver = options?.driver ?? defaultDriver<TEvent>();
  const { prefix } = driver;
  const name = config.name ?? DEFAULT_NAME;
  unjwtRethrown(() => assertSessionConfig(config, { name, prefix }));
  const seconds = (value: ExpiresIn | undefined, label: string) =>
    value === undefined ? undefined : durationSeconds(value, { label, prefix }) * 1000;
  const bytes = config.bytes ?? 32;
  if (!Number.isInteger(bytes) || bytes < 16 || bytes > MAX_TOKEN_BYTES) {
    throw configError(
      `A session token needs a whole number of 16 to ${MAX_TOKEN_BYTES} random bytes, got ${bytes}.`,
      { prefix },
    );
  }
  const { store } = config;
  const context: OpaqueContext<TData, TEvent> = {
    name,
    prefix,
    bytes,
    generateId: config.generateId ?? (() => crypto.randomUUID()),
    maxAge: seconds(config.maxAge, 'A session\'s "maxAge"'),
    idle: seconds(config.idle, 'A session\'s "idle"'),
    now,
    transport: sessionTransportOptions(config, { name }),
    store: typeof store === "function" ? store : () => store,
  };

  return {
    use: (event) => bindSession(driver, event, context),
    issue: async (data) => {
      const { token } = await createOpaqueToken({ bytes });
      const at = now();
      const record: OpaqueSessionRecord<TData> = {
        id: mintId(context),
        createdAt: at,
        updatedAt: at,
        expiresAt: endOf(context, { createdAt: at, now: at }),
        data,
      };
      await context.store().save(token, record);
      return token;
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
