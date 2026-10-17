import { UnauthError } from "../_internal/error.ts";
import type { ProvenIdentity } from "./flow/types.ts";

/** A provider account, as `IdentityStore` looks it up. */
export interface IdentityRef {
  provider: string;
  subject: string;
}

/**
 * The application's user and identity records, as {@link signIn} needs them. Tokens reach the
 * store only inside `identity.tokens`; unauth keeps none.
 */
export interface IdentityStore<TUser extends { id: string }> {
  /** The user owning this provider account, if any. */
  findByIdentity: (ref: IdentityRef) => Promise<TUser | undefined>;
  /** Creates a user owning this provider account. */
  create: (identity: ProvenIdentity<unknown>) => Promise<TUser>;
  /** Attaches this provider account to an existing user and returns that user. */
  link: (userId: string, identity: ProvenIdentity<unknown>) => Promise<TUser>;
}

/** Options of {@link signIn}. */
export interface SignInOptions<TUser extends { id: string }> {
  identities: IdentityStore<TUser>;
  /** Attach the account to this user instead of signing in: a callback's `link`. */
  link?: { userId: string };
  /**
   * The user signed in now. A `link` naming anyone else (or given with no one signed in) throws
   * `ERR_AUTHN_LINK_CHANGED`: the session changed between the two legs of the flow.
   */
  currentUserId?: string;
}

/** Who signed in, and whether this sign-in created or linked them. */
export interface SignInResult<TUser> {
  user: TUser;
  created: boolean;
  linked: boolean;
}

/**
 * Resolves a proven identity to the application's user: the account's owner when it has one;
 * with `link`, the linking user, who must be `currentUserId` (else `ERR_AUTHN_LINK_CHANGED`, 409,
 * before any store call); an account owned by someone else is `ERR_AUTHN_LINK_CONFLICT`, 409, as
 * merging users is the application's call; otherwise a new user. Accounts are never matched by
 * email.
 */
export async function signIn<TUser extends { id: string }>(
  identity: ProvenIdentity<unknown>,
  options: SignInOptions<TUser>,
): Promise<SignInResult<TUser>> {
  const { identities, link } = options;
  if (link && link.userId !== options.currentUserId) {
    throw new UnauthError(
      "[unauth/n] The account link was asked for by another session.",
      "ERR_AUTHN_LINK_CHANGED",
      { status: 409, cause: { linkUserId: link.userId } },
    );
  }
  const owner = await identities.findByIdentity({
    provider: identity.provider,
    subject: identity.subject,
  });

  if (link) {
    if (owner === undefined) {
      return { user: await identities.link(link.userId, identity), created: false, linked: true };
    }
    if (owner.id !== link.userId) {
      throw new UnauthError(
        "[unauth/n] This account is already linked to another user.",
        "ERR_AUTHN_LINK_CONFLICT",
        { status: 409, cause: { provider: identity.provider } },
      );
    }
    return { user: owner, created: false, linked: false };
  }

  if (owner !== undefined) return { user: owner, created: false, linked: false };
  return { user: await identities.create(identity), created: true, linked: false };
}
