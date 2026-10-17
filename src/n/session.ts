import {
  type ExpiresIn,
  type OpenedSessionState,
  type SessionConfigJWE,
  type SessionConfigJWS,
  type SessionContext,
  type SessionData,
  type SessionDefinition,
  type SessionHooksJWE,
  type SessionHooksJWS,
  type SessionIssueOptions,
  type SessionManager,
  type SessionUpdate,
  defineJWESession,
} from "unjwt/session";
import type { AuthConfigInput } from "./_session-config.ts";
import { composeAuthSession } from "./_session-define.ts";
import { asAuthenticated, authenticatedData } from "./_session-manager.ts";

/** Session data an application declares. */
// oxlint-disable-next-line typescript/no-explicit-any -- an interface has no implicit index signature
export type AuthSessionRecord = Record<string, any>;

/** What the session token carries: the application's data plus the reserved `authenticatedAt`. */
export type AuthSessionData<TData extends AuthSessionRecord> = TData & {
  /** When the session last authenticated, in ms. Set only by `authenticate()`. */
  authenticatedAt?: number;
};

/** Data of a session that authenticated, as {@link requireSession} returns it. */
export type AuthenticatedData<TData extends AuthSessionRecord> = SessionData<
  AuthSessionData<TData>
> & { authenticatedAt: number };

/** A session's state as it stood before a change, as `onSignOut` receives it. */
export type AuthSessionSnapshot<TData extends AuthSessionRecord> = Pick<
  SessionManager<AuthSessionData<TData>, ExpiresIn>,
  "id" | "createdAt" | "expiresAt" | "data" | "token"
>;

/**
 * The manager `use()` returns: unjwt's session manager, with `authenticatedAt` kept out of
 * `update()` and two authentication members.
 */
export interface AuthSessionManager<
  TData extends AuthSessionRecord,
> extends AuthSessionSnapshot<TData> {
  /** Merges `update` and reissues the token; an `authenticatedAt` in it is dropped. */
  update: (
    update?: SessionUpdate<TData>,
    options?: SessionIssueOptions,
  ) => Promise<AuthSessionManager<TData>>;
  /** Empties the session and expires its cookie; fires `onSignOut` when it had authenticated. */
  clear: () => Promise<AuthSessionManager<TData>>;
  /**
   * Marks the session authenticated now: merges `data` like `update()`, sets `authenticatedAt`
   * and reissues the token under a new `id`. Data from before stays unless `data` overwrites it,
   * so `clear()` first when another identity may have used the session. Fires `onSignIn`.
   */
  authenticate: (
    data: SessionData<TData>,
    options?: SessionIssueOptions,
  ) => Promise<AuthSessionManager<TData>>;
  /**
   * Throws unless the session authenticated within `maxAge` (seconds or `"5m"`, `"1h"`…):
   * `ERR_AUTHN_UNAUTHENTICATED` without an authenticated session, `ERR_AUTHN_REAUTH_REQUIRED`
   * when it is older. Both carry status 401.
   */
  requireRecent: (maxAge: ExpiresIn) => void;
}

/** One authentication session, defined once and used on every request. */
export interface AuthSessionDefinition<TData extends AuthSessionRecord, TContext = SessionContext> {
  /** Reads the request's session once; later calls on the same request share its state. */
  use: (context: TContext) => Promise<AuthSessionManager<TData>>;
  /** The token the request carries, unopened. */
  token: (context: TContext) => string | undefined;
  /** Mints a token for `data` without a request; an `authenticatedAt` in it is dropped. */
  issue: (data?: Partial<SessionData<TData>>, options?: SessionIssueOptions) => Promise<string>;
  /** Opens a token into session state; only the key-lookup hook runs. */
  open: (token: string) => Promise<OpenedSessionState<AuthSessionData<TData>, ExpiresIn>>;
}

/**
 * Authentication hooks, run in front of unjwt's session hooks. `TArgs` names the request as the
 * unjwt entry does: `{ context }` on `unjwt/session`.
 */
export interface AuthSessionHooks<
  TData extends AuthSessionRecord,
  TArgs extends Record<string, unknown> = { context: SessionContext },
> {
  /** Runs once per request on a session read from its token; `true` clears the session. */
  isRevoked?: (args: TArgs & { session: AuthSessionManager<TData> }) => boolean | Promise<boolean>;
  /**
   * Runs when `rolling` reissues the session: `false` clears it (`onSignOut` with
   * `reason: "refresh"`), an object is merged into it, `undefined` keeps it as it is. Under TS 7 an
   * async arrow returning only `false` needs `false as const`.
   *
   * The roll itself, a new token under a new `id`, is unjwt's `onUpdate` with
   * `trigger: "rolling"`, which passes through unchanged: track a session's family of ids there.
   */
  refresh?: (
    args: TArgs & { session: AuthSessionManager<TData> },
  ) =>
    | Partial<SessionData<TData>>
    | false
    | undefined
    | Promise<Partial<SessionData<TData>> | false | undefined>;
  /** Fires after `authenticate()` reissued the session. */
  onSignIn?: (args: TArgs & { session: AuthSessionManager<TData> }) => void | Promise<void>;
  /**
   * Fires after an authenticated session was cleared: the end of its family of ids (each roll is an
   * `onUpdate` with `trigger: "rolling"`). `reason` (closed) tells why: `"clear"` for the app's
   * `clear()`, `"revoked"` for `isRevoked` returning `true`, `"refresh"` for `refresh` returning
   * `false`, as when the user is gone.
   */
  onSignOut?: (
    args: TArgs & {
      oldSession: AuthSessionSnapshot<TData>;
      reason: "clear" | "revoked" | "refresh";
    },
  ) => void | Promise<void>;
}

/** The auth options layered over an unjwt session config. */
export interface AuthSessionOptions {
  /** @default "7D" */
  maxAge?: ExpiresIn;
  /**
   * Reissue the session on read so `exp` slides: `true` on every read, a duration once less than
   * that remains, `false` never.
   *
   * @default a quarter of `maxAge` remaining
   */
  rolling?: boolean | ExpiresIn;
}

/**
 * An auth session config over any unjwt entry's session config `TBase`, whose hooks name the
 * request as `TArgs` (`{ context }`, `{ event }`). Framework glue builds its config from it.
 */
export type AuthSessionConfigOf<
  TData extends AuthSessionRecord,
  TBase extends { hooks?: object },
  TArgs extends Record<string, unknown>,
> = Omit<TBase, "maxAge" | "rolling" | "hooks"> &
  AuthSessionOptions & { hooks?: NonNullable<TBase["hooks"]> & AuthSessionHooks<TData, TArgs> };

/** {@link defineAuthSession} config over a JWE (encrypted) session, the default. */
export interface AuthSessionConfigJWE<TData extends AuthSessionRecord, TContext = SessionContext>
  extends
    Omit<
      SessionConfigJWE<AuthSessionData<TData>, ExpiresIn, TContext>,
      "maxAge" | "rolling" | "hooks"
    >,
    AuthSessionOptions {
  hooks?: SessionHooksJWE<AuthSessionData<TData>, ExpiresIn, TContext> &
    AuthSessionHooks<TData, { context: TContext }>;
}

/** {@link defineAuthSession} config over a JWS (signed, readable) session. */
export interface AuthSessionConfigJWS<TData extends AuthSessionRecord, TContext = SessionContext>
  extends
    Omit<
      SessionConfigJWS<AuthSessionData<TData>, ExpiresIn, TContext>,
      "maxAge" | "rolling" | "hooks"
    >,
    AuthSessionOptions {
  hooks?: SessionHooksJWS<AuthSessionData<TData>, ExpiresIn, TContext> &
    AuthSessionHooks<TData, { context: TContext }>;
}

/**
 * Defines the authentication session: an unjwt session (`defineJWESession` from `unjwt/session`
 * unless `options.define` names another factory) plus `authenticatedAt`, revocation, refresh on
 * roll and sign-in/sign-out events.
 */
export function defineAuthSession<TData extends AuthSessionRecord, TContext = SessionContext>(
  config: AuthSessionConfigJWE<TData, TContext>,
  options?: {
    define?: (
      config: SessionConfigJWE<AuthSessionData<TData>, ExpiresIn, TContext>,
    ) => SessionDefinition<TContext, AuthSessionData<TData>, ExpiresIn>;
  },
): AuthSessionDefinition<TData, TContext>;
export function defineAuthSession<TData extends AuthSessionRecord, TContext = SessionContext>(
  config: AuthSessionConfigJWS<TData, TContext>,
  options: {
    define: (
      config: SessionConfigJWS<AuthSessionData<TData>, ExpiresIn, TContext>,
    ) => SessionDefinition<TContext, AuthSessionData<TData>, ExpiresIn>;
  },
): AuthSessionDefinition<TData, TContext>;
export function defineAuthSession(
  config: AuthConfigInput,
  options?: { define?: object },
): AuthSessionDefinition<AuthSessionRecord, unknown> {
  return composeAuthSession(config, { define: options?.define ?? defineJWESession });
}

/** The data of an authenticated session; throws `ERR_AUTHN_UNAUTHENTICATED` (401) otherwise. */
export function requireSession<TData extends AuthSessionRecord>(
  session: AuthSessionManager<TData>,
): AuthenticatedData<TData> {
  return authenticatedData(session);
}

/** The data of an authenticated session, or `undefined` without one. */
export function optionalSession<TData extends AuthSessionRecord>(
  session: AuthSessionManager<TData>,
): AuthenticatedData<TData> | undefined {
  return session.id === undefined ? undefined : asAuthenticated(session.data);
}
