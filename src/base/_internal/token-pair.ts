/**
 * Read-only session snapshot.
 */
export interface SessionSnapshot<TData> {
  /** Unique identifier for this session (jti). */
  readonly id: string;
  /** JWT payload (excluding jti, exp, iat). */
  readonly data: TData;
  /** Timestamp in milliseconds when this session was created (iat). */
  readonly createdAt: number;
  /** Timestamp in milliseconds when this session will expire (exp). */
  readonly expiresAt: number;
}

/** Anything carrying session state: unjwt's manager or the raw state it mirrors. */
interface SnapshotSource<TData> {
  readonly id: string | undefined;
  readonly data: TData;
  readonly createdAt: number;
  readonly expiresAt: number;
}

/** Copies the identifying fields of a session; `undefined` when there is no session. */
export function snapshotSession<TData>(
  session: SnapshotSource<TData> & { id: string },
): SessionSnapshot<TData>;
export function snapshotSession<TData>(
  session: SnapshotSource<TData>,
): SessionSnapshot<TData> | undefined;
export function snapshotSession<TData>(
  session: SnapshotSource<TData>,
): SessionSnapshot<TData> | undefined {
  if (session.id === undefined) return undefined;
  return {
    id: session.id,
    data: session.data,
    createdAt: session.createdAt,
    expiresAt: session.expiresAt,
  };
}
