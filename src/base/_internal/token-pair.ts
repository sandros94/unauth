/**
 * Read-only session snapshot.
 */
export interface SessionSnapshot<TData> {
  /** Unique identifier for this session (jti). */
  readonly id: string;
  /** JWT payload (excluding jti, exp, iat). */
  readonly data: TData;
  /** Timestamp in seconds when this session was created (iat). */
  readonly createdAt: number;
  /** Timestamp in seconds when this session will expire (exp). */
  readonly expiresAt: number;
}
