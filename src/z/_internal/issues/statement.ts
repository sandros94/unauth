import { isRecord } from "../../../_internal/shared.ts";
import type { ValidationIssue } from "../../types.ts";
import type { CompiledCatalog } from "../compiled.ts";
import { permissionUnknown, placeOutside, roleUnknown, statementEnded } from "../errors.ts";
import { isPattern, isToken } from "../grammar.ts";
import { issueOf } from "./issue.ts";
import { isCanonicalKey, keyMalformed } from "../keys.ts";
import { expand } from "../permissions.ts";
import type { RoleReader } from "../roles.ts";
import { isFilled, isKind, statementMalformed } from "../statements.ts";
import { fits } from "../structure.ts";
import { isTime, timeMalformed } from "../time.ts";

/**
 * Every problem of a statement being validated at `time`, as the model's validation refuses it:
 * its form first, member by member, then a permission or a role neither the catalog nor `roles`
 * holds, then a place that does not fit, then an end already past. A check that needs a member
 * another check found malformed is skipped. With no valid kind nothing is looked up for the value,
 * since the kind says whether it names a permission or a role: it is only refused when it is in
 * the form of neither.
 */
export function statementIssues(
  catalog: CompiledCatalog,
  roles: RoleReader,
  statement: unknown,
  time: number,
): ValidationIssue[] {
  if (!isRecord(statement)) return [issueOf(statementMalformed(statement), [])];
  const { kind, subject, value, place, expiresAt } = statement;
  const form: ValidationIssue[] = [];
  const found: ValidationIssue[] = [];
  const shape = (member: string) => form.push(issueOf(statementMalformed(statement), [member]));
  if (!isKind(kind)) shape("kind");
  if (!isFilled(subject)) shape("subject");
  const named = isKind(kind) ? namedBy(kind, value) : undefined;
  if (isKind(kind) ? !named : !isPattern(value) && !isToken(value)) shape("value");
  const key = place === undefined ? "/" : isCanonicalKey(place) ? place : undefined;
  if (key === undefined) form.push(issueOf(keyMalformed(place), ["place"]));
  if (expiresAt !== undefined && !isTime(expiresAt)) {
    form.push(issueOf(timeMalformed(expiresAt), ["expiresAt"]));
  }
  if (named?.role === true && !roles.exists(named.value)) {
    found.push(issueOf(roleUnknown(named.value), ["value"]));
  }
  if (named?.role === false && expand(catalog, named.value).size === 0) {
    found.push(issueOf(permissionUnknown(named.value), ["value"]));
  }
  if (key !== undefined && !fits(catalog, key)) found.push(issueOf(placeOutside(key), ["place"]));
  if (isTime(expiresAt) && expiresAt <= time) {
    found.push(issueOf(statementEnded(expiresAt), ["expiresAt"]));
  }
  return [...form, ...found];
}

/** What the value names for the kind, `undefined` when it is not in its form for the kind. */
function namedBy(kind: string, value: unknown): { role: boolean; value: string } | undefined {
  if (kind !== "assign" && isPattern(value)) return { role: false, value };
  if (kind === "assign" && isToken(value)) return { role: true, value };
  return undefined;
}
