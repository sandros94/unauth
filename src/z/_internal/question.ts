import { isRecord } from "../../_internal/shared.ts";
import type { CompiledCatalog } from "./compiled.ts";
import { malformed, questionInvalid } from "./errors.ts";
import { assertQuestionPermission } from "./permissions.ts";
import { checkPlace } from "./structure.ts";

/** What a question asks, checked: one declared, concrete permission, and a canonical place that fits. */
export interface ReadAsked {
  readonly permission: string;
  readonly place: string;
}

/**
 * Checks what a question asks, whoever it is asked of: `permission` and `place`.
 *
 * @throws `ERR_AUTHZ_MALFORMED` (`question`) for a question that is not an object.
 * @throws `ERR_AUTHZ_QUESTION_INVALID` (`empty`) for a permission that is absent, not a string or
 * empty.
 * @throws what `assertQuestionPermission` throws for the permission and `checkPlace` for the place.
 */
export function readAsked(catalog: CompiledCatalog, question: unknown): ReadAsked {
  if (!isRecord(question)) throw questionError(question);
  const { permission, place } = question;
  if (typeof permission !== "string" || permission === "") throw questionInvalid("empty");
  return {
    permission: assertQuestionPermission(catalog, permission),
    place: checkPlace(catalog, place),
  };
}

/**
 * The subject and groups of a question asked of statements.
 *
 * @throws `ERR_AUTHZ_MALFORMED` (`question`) for a question that is not an object, a subject that
 * is not a non-empty string, or groups that are not a list of strings.
 */
export function readAsker(question: unknown): { subject: string; groups: string[] } {
  if (!isRecord(question)) throw questionError(question);
  const { subject, groups } = question;
  if (typeof subject !== "string" || subject === "") throw questionError(subject);
  if (groups === undefined) return { subject, groups: [] };
  if (!Array.isArray(groups) || !groups.every((group) => typeof group === "string")) {
    throw questionError(groups);
  }
  return { subject, groups: [...groups] };
}

function questionError(value: unknown) {
  return malformed("The question is not in its shape.", { what: "question", value });
}
