import { stringField } from "./http/shared.ts";
import type { ProfileResult } from "../types.ts";

/**
 * The normalized identity of an account payload using the OpenID Connect standard claims, with
 * the common OAuth 2.0 spellings as fallbacks (`id`, `avatar_url`). `subject` is empty when the
 * payload names none; the flow refuses that.
 */
export function standardProfile<TProfile extends Record<string, unknown>>(
  profile: TProfile,
): ProfileResult<TProfile> {
  const id = profile.sub ?? profile.id;
  const result: ProfileResult<TProfile> = {
    subject: typeof id === "string" || typeof id === "number" ? String(id) : "",
    profile,
  };
  const name = stringField(profile, "name") ?? stringField(profile, "preferred_username");
  if (name !== undefined) result.name = name;
  const email = stringField(profile, "email");
  if (email !== undefined) result.email = email;
  const verified = profile.email_verified;
  if (typeof verified === "boolean") result.emailVerified = verified;
  else if (verified === "true" || verified === "false") result.emailVerified = verified === "true";
  const avatar = stringField(profile, "picture") ?? stringField(profile, "avatar_url");
  if (avatar !== undefined) result.avatar = avatar;
  return result;
}
