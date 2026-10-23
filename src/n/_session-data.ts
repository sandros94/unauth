import type { ProvenIdentity } from "./flow/types.ts";

/** The default session data a sign-in writes; extend it with the application's own members. */
export interface AuthSessionData {
  /** The provider's `id`. */
  provider: string;
  /** The account's stable identifier at that provider. */
  subject: string;
  name?: string;
  email?: string;
  /** Whether the provider vouches for `email`; absent when it does not say. */
  emailVerified?: boolean;
  avatar?: string;
  /**
   * When the sign-in completed, in ms since the epoch; set every time one completes. The one
   * member not read from the identity.
   */
  signedInAt: number;
}

/** The {@link AuthSessionData} of a proven identity: neither its `profile` nor its `tokens`. */
export function toSessionData(
  identity: ProvenIdentity<unknown>,
  options: { now: number },
): AuthSessionData {
  const data: AuthSessionData = {
    provider: identity.provider,
    subject: identity.subject,
    signedInAt: options.now,
  };
  if (identity.name !== undefined) data.name = identity.name;
  if (identity.email !== undefined) data.email = identity.email;
  if (identity.emailVerified !== undefined) data.emailVerified = identity.emailVerified;
  if (identity.avatar !== undefined) data.avatar = identity.avatar;
  return data;
}
