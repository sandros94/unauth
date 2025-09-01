import type { OIDCUserInfoProfile } from "./types";

/**
 * Build a compliant UserInfo response by picking allowed standard claims from a provided profile.
 */
export function buildUserInfo<T extends Record<string, unknown>>(
  profile: OIDCUserInfoProfile,
): OIDCUserInfoProfile & T {
  const out: Record<string, unknown> = {};

  // Required claim: sub must be a string
  if (typeof profile.sub !== "string") {
    throw new TypeError("[OIDC] userinfo.sub must be a string");
  }
  out.sub = profile.sub;

  // Standard string claims: include only if type matches
  const stringClaims = [
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "email",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "phone_number",
  ] as const;
  for (const key of stringClaims) {
    const v = (profile)[key];
    if (typeof v === "string" && v) {
      (out)[key] = v;
    }
  }

  // Standard boolean claims
  const booleanClaims = ["email_verified", "phone_number_verified"] as const;
  for (const key of booleanClaims) {
    const v = (profile)[key];
    if (typeof v === "boolean") {
      (out)[key] = v;
    }
  }

  // Optional: address (object) and updated_at (number)
  const addr = (profile).address;
  if (addr && typeof addr === "object" && !Array.isArray(addr)) {
    out.address = addr as Record<string, unknown>;
  }
  const updatedAt = (profile).updated_at;
  if (typeof updatedAt === "number") {
    out.updated_at = updatedAt;
  }

  // Pass through non-standard own properties safely (prevent prototype pollution)
  const standardKeys = new Set([
    "sub",
    ...stringClaims,
    ...booleanClaims,
    "address",
    "updated_at",
  ]);
  for (const [k, v] of Object.entries(profile)) {
    if (standardKeys.has(k)) continue;
    if (k === "__proto__" || k === "prototype" || k === "constructor") {
      continue;
    }
    if (v === undefined || typeof v === "function") continue;
    (out)[k] = v as unknown;
  }

  return out as OIDCUserInfoProfile & T;
}
