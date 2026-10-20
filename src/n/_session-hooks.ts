import type { ExpiresIn, SessionManager } from "unjwt/session";
import type { AuthSessionHooks, AuthSessionRecord, AuthSessionSnapshot } from "./session.ts";
import {
  AUTHENTICATED_AT,
  authSessionManager,
  requireAuthenticated,
  withoutReserved,
} from "./_session-manager.ts";

type Manager = SessionManager<AuthSessionRecord, ExpiresIn>;
type HookArgs = Record<string, unknown>;
type Hook<A> = ((args: A) => void | Promise<void>) | undefined;

/** The session hooks the composition reads; every other hook passes through untouched. */
export interface ComposableHooks extends AuthSessionHooks<AuthSessionRecord, HookArgs> {
  onRead?: Hook<HookArgs & { session: Manager }>;
  onUpdate?: Hook<
    HookArgs & {
      session: Manager;
      oldSession: AuthSessionSnapshot<AuthSessionRecord>;
      trigger: string;
    }
  >;
  onClear?: Hook<HookArgs & { oldSession: AuthSessionSnapshot<AuthSessionRecord> | undefined }>;
  [hook: string]: unknown;
}

type SignOutReason = "clear" | "revoked" | "refresh";

/**
 * unjwt session hooks with the auth hooks run in front: `isRevoked` on `onRead`, `refresh` on a
 * rolling `onUpdate`, `onSignIn` on an `onUpdate` that moved `authenticatedAt`, `onSignOut` on the
 * `onClear` of an authenticated session.
 */
export function composeAuthHooks(hooks: ComposableHooks | undefined): Record<string, unknown> {
  if (!hooks) return {};
  const { isRevoked, refresh, onSignIn, onSignOut, onRead, onUpdate, onClear, ...rest } = hooks;
  const composed: Record<string, unknown> = { ...rest, onRead, onUpdate, onClear };
  /** Why a session id is being cleared, while the hooks' own `clear()` runs; else it is `clear()`. */
  const clearing = new Map<string, SignOutReason>();
  const clearFor = async (session: Manager, reason: SignOutReason): Promise<void> => {
    const id = session.id;
    if (id !== undefined) clearing.set(id, reason);
    try {
      await session.clear();
    } finally {
      if (id !== undefined) clearing.delete(id);
    }
  };

  if (isRevoked) {
    composed.onRead = async (args: HookArgs & { session: Manager }) => {
      const session = authSessionManager(args.session);
      if (await isRevoked({ ...requestArgs(args), session })) {
        await clearFor(args.session, "revoked");
        return;
      }
      await onRead?.(args);
    };
  }

  if (refresh || onSignIn) {
    composed.onUpdate = async (
      args: HookArgs & {
        session: Manager;
        oldSession: AuthSessionSnapshot<AuthSessionRecord>;
        trigger: string;
      },
    ) => {
      const session = authSessionManager(args.session);
      if (args.trigger === "rolling" && refresh) {
        const verdict = await refresh({ ...requestArgs(args), session });
        // The roll already happened: report it before changing it, so ids chain in `onUpdate`.
        await onUpdate?.(args);
        if (verdict === false) await clearFor(args.session, "refresh");
        else if (verdict) await args.session.update(withoutReserved(verdict));
        return;
      }
      if (onSignIn && signedIn(args)) {
        await onSignIn({ ...requestArgs(args), session: requireAuthenticated(session) });
      }
      await onUpdate?.(args);
    };
  }

  if (onSignOut) {
    composed.onClear = async (
      args: HookArgs & { oldSession: AuthSessionSnapshot<AuthSessionRecord> | undefined },
    ) => {
      const { oldSession } = args;
      if (oldSession?.data[AUTHENTICATED_AT] !== undefined) {
        const reason =
          (oldSession.id === undefined ? undefined : clearing.get(oldSession.id)) ?? "clear";
        await onSignOut({ ...requestArgs(args), oldSession, reason });
      }
      await onClear?.(args);
    };
  }

  return composed;
}

/** An update that moved `authenticatedAt` is a sign-in; nothing else sets it. */
function signedIn(args: {
  session: Manager;
  oldSession: AuthSessionSnapshot<AuthSessionRecord>;
  trigger: string;
}): boolean {
  const now: unknown = args.session.data[AUTHENTICATED_AT];
  return (
    args.trigger === "update" && now !== undefined && now !== args.oldSession.data[AUTHENTICATED_AT]
  );
}

/** The hook arguments naming the request (`context`, `event`…), without the session-owned ones. */
function requestArgs(args: HookArgs): HookArgs {
  const {
    session: _session,
    oldSession: _oldSession,
    trigger: _trigger,
    config: _config,
    ...rest
  } = args;
  return rest;
}
