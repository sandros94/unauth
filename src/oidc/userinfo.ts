import type { OIDCUserInfoProfile } from "./types";

/**
 * Build a compliant UserInfo response by picking allowed standard claims from a provided profile.
 */
export function buildUserInfo(
  profile: OIDCUserInfoProfile,
): OIDCUserInfoProfile {
  const {
    sub,
    name,
    given_name,
    family_name,
    middle_name,
    nickname,
    preferred_username,
    profile: profileUrl,
    picture,
    website,
    email,
    email_verified,
    gender,
    birthdate,
    zoneinfo,
    locale,
    phone_number,
    phone_number_verified,
    address,
    updated_at,
  } = profile;

  return {
    sub,
    ...(name ? { name } : {}),
    ...(given_name ? { given_name } : {}),
    ...(family_name ? { family_name } : {}),
    ...(middle_name ? { middle_name } : {}),
    ...(nickname ? { nickname } : {}),
    ...(preferred_username ? { preferred_username } : {}),
    ...(profileUrl ? { profile: profileUrl } : {}),
    ...(picture ? { picture } : {}),
    ...(website ? { website } : {}),
    ...(email ? { email } : {}),
    ...(typeof email_verified === "boolean" ? { email_verified } : {}),
    ...(gender ? { gender } : {}),
    ...(birthdate ? { birthdate } : {}),
    ...(zoneinfo ? { zoneinfo } : {}),
    ...(locale ? { locale } : {}),
    ...(phone_number ? { phone_number } : {}),
    ...(typeof phone_number_verified === "boolean"
      ? { phone_number_verified }
      : {}),
    ...(address ? { address } : {}),
    ...(updated_at ? { updated_at } : {}),
  };
}
