import { UnauthError } from "../../../error.ts";
import type { ValidationIssue } from "../../types.ts";

/** The issue an error of validation stands for, about the member at `path`. */
export function issueOf(
  error: UnauthError<ValidationIssue["code"]>,
  path: ValidationIssue["path"],
): ValidationIssue {
  const { code, message, cause } = error;
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the factory of each code gives the cause its map declares
  return { code, path, message, cause } as ValidationIssue;
}

/** The error an issue stands for, with the status of every refusal of validation. */
export function errorOf(issue: ValidationIssue): UnauthError<ValidationIssue["code"]> {
  return new UnauthError(issue.message, issue.code, { status: 400, cause: issue.cause });
}
