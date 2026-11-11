import { isRecord } from "../../_internal/shared.ts";
import type { CompiledCatalog } from "./compiled.ts";
import { malformed } from "./errors.ts";
import {
  type ReadStatement,
  identityOf,
  isPermanentManagement,
  readStatements,
} from "./statements.ts";

/**
 * The permanent managements among the statements handed in as the root's.
 *
 * @throws what `readStatements` throws, `ERR_AUTHZ_MALFORMED` (`statement`) for `managers` that is
 * not a list among them.
 */
export function readManagers(catalog: CompiledCatalog, managers: unknown): ReadStatement[] {
  return readStatements(catalog, managers).filter(isPermanentManagement);
}

/**
 * {@link readManagers}, `undefined` when none were handed in: then nothing proves the root holds
 * one, or that it holds none.
 */
export function readManagersIfGiven(
  catalog: CompiledCatalog,
  managers: unknown,
): ReadStatement[] | undefined {
  return managers === undefined ? undefined : readManagers(catalog, managers);
}

/**
 * Checks the statement of genesis for its one form: a permanent allow of `*` at the root, about a
 * subject that is a non-empty string.
 *
 * @throws `ERR_AUTHZ_MALFORMED` (`statement`) for anything else.
 */
export function assertGenesisStatement(statement: unknown): void {
  if (
    !isRecord(statement) ||
    statement.kind !== "allow" ||
    statement.value !== "*" ||
    (statement.place !== undefined && statement.place !== "/") ||
    statement.expiresAt !== undefined ||
    typeof statement.subject !== "string" ||
    statement.subject === ""
  ) {
    throw malformed("The statement is not a permanent allow of every permission at the root.", {
      what: "statement",
      value: statement,
    });
  }
}

/** Whether a statement has the identity of a permanent management: an allow of `*` at the root. */
export function isRootIdentity(statement: ReadStatement): boolean {
  return statement.kind === "allow" && statement.value === "*" && statement.place === "/";
}

/**
 * Whether the root could lose its last permanent management once `statement` is removed, or
 * placed with an end over one of the same identity. Always so without `managers`. A root that
 * holds none has none to lose. A statement of another identity, or a permanent management placed,
 * never takes one away.
 */
export function leavesRootEmpty(
  action: "place" | "remove",
  statement: ReadStatement,
  managers: readonly ReadStatement[] | undefined,
): boolean {
  if (!isRootIdentity(statement)) return false;
  if (action === "place" && statement.expiresAt === undefined) return false;
  if (!managers) return true;
  if (managers.length === 0) return false;
  const gone = identityOf(statement);
  return managers.every((manager) => identityOf(manager) === gone);
}
