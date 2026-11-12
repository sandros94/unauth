import { defineAuthz } from "unauth/z";

export const authz = defineAuthz({
  permissions: [
    "repo:read",
    "repo:triage",
    "repo:write",
    "repo:maintain",
    "repo:admin",
    "internal-repo:read",
    "branch-protection:bypass",
    "ruleset:bypass",
    "rules:manage",
    "access:manage",
    "member:manage",
    "enterprise:manage",
  ],
  implies: {
    "repo:admin": ["repo:maintain"],
    "repo:maintain": ["repo:write"],
    "repo:write": ["repo:triage"],
    "repo:triage": ["repo:read"],
    "repo:read": ["internal-repo:read"],
  },
  presets: {
    "read": ["repo:read"],
    "triage": ["repo:triage"],
    "write": ["repo:write"],
    "maintain": ["repo:maintain"],
    "admin": ["repo:admin", "rules:manage", "branch-protection:bypass", "access:manage"],
    "owner": ["admin", "member:manage"],
    "enterprise-owner": ["enterprise:manage"],
    "ruleset-bypass": ["ruleset:bypass"],
  },
  places: {
    "/": ["enterprise", "org"],
    "enterprise": ["org"],
    "org": ["repo"],
    "repo": ["ruleset"],
  },
});

export type Permission = (typeof authz.catalog.data.permissions)[number];

export const REPOSITORY_ROLES = ["read", "triage", "write", "maintain", "admin"] as const;

export type RepositoryRole = (typeof REPOSITORY_ROLES)[number];

export function isRepositoryRole(value: unknown): value is RepositoryRole {
  return REPOSITORY_ROLES.some((role) => role === value);
}
