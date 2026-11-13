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
  if (!isRecord(question)) {
    throw malformed("The question is not in its shape.", { what: "question", value: question });
  }
  const { permission, place } = question;
  if (typeof permission !== "string" || permission === "") throw questionInvalid("empty");
  return {
    permission: assertQuestionPermission(catalog, permission),
    place: checkPlace(catalog, place),
  };
}
