import type { UnauthErrorCauseMap } from "../../error.ts";
import { UnauthError } from "../../error.ts";

/** The `cause` of `ERR_AUTHZ_MALFORMED`. */
export type MalformedCause = UnauthErrorCauseMap["ERR_AUTHZ_MALFORMED"];

/** The `cause` of `ERR_AUTHZ_CATALOG_INVALID`. */
export type CatalogInvalidCause = UnauthErrorCauseMap["ERR_AUTHZ_CATALOG_INVALID"];

/** The `cause` of `ERR_AUTHZ_ROLE_INVALID`. */
export type RoleInvalidCause = UnauthErrorCauseMap["ERR_AUTHZ_ROLE_INVALID"];

/** `ERR_AUTHZ_MALFORMED` (400). */
export function malformed(
  message: string,
  cause: MalformedCause,
): UnauthError<"ERR_AUTHZ_MALFORMED"> {
  return new UnauthError(message, "ERR_AUTHZ_MALFORMED", { status: 400, cause });
}

/** `ERR_AUTHZ_CATALOG_INVALID` (500). */
export function catalogInvalid(
  message: string,
  cause: CatalogInvalidCause,
): UnauthError<"ERR_AUTHZ_CATALOG_INVALID"> {
  return new UnauthError(message, "ERR_AUTHZ_CATALOG_INVALID", { status: 500, cause });
}

/** `ERR_AUTHZ_PERMISSION_UNKNOWN` (400) for `permission`, a permission or a pattern. */
export function permissionUnknown(permission: string): UnauthError<"ERR_AUTHZ_PERMISSION_UNKNOWN"> {
  return new UnauthError("The permission is not in the catalog.", "ERR_AUTHZ_PERMISSION_UNKNOWN", {
    status: 400,
    cause: { permission },
  });
}

/** `ERR_AUTHZ_PLACE_OUTSIDE` (400) for a canonical key that does not fit the structure. */
export function placeOutside(place: string): UnauthError<"ERR_AUTHZ_PLACE_OUTSIDE"> {
  return new UnauthError(
    "The place does not fit the catalog's structure.",
    "ERR_AUTHZ_PLACE_OUTSIDE",
    { status: 400, cause: { place } },
  );
}

/** `ERR_AUTHZ_QUESTION_INVALID` (400). */
export function questionInvalid(
  reason: "empty" | "wildcard",
): UnauthError<"ERR_AUTHZ_QUESTION_INVALID"> {
  return new UnauthError("The question cannot be answered.", "ERR_AUTHZ_QUESTION_INVALID", {
    status: 400,
    cause: { reason },
  });
}

/** `ERR_AUTHZ_ROLE_INVALID` (400). */
export function roleInvalid(
  message: string,
  cause: RoleInvalidCause,
): UnauthError<"ERR_AUTHZ_ROLE_INVALID"> {
  return new UnauthError(message, "ERR_AUTHZ_ROLE_INVALID", { status: 400, cause });
}
