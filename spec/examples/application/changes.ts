import type { DatabaseSync } from "node:sqlite";
import type { Authz, Statement, ValidationIssue } from "unauth/z";
import { presetsOf, readRoles } from "../storage/roles.ts";

export function statementIssues(
  db: DatabaseSync,
  authz: Authz,
  statements: readonly Statement[],
): ValidationIssue[] {
  const presets = presetsOf(authz);
  const named = statements
    .filter(({ kind, value }) => kind === "assign" && !presets.includes(value))
    .map(({ value }) => value);
  const roles = named.length === 0 ? [] : readRoles(db, named);
  return statements.flatMap((statement) => authz.validateStatement(statement, { roles }));
}
