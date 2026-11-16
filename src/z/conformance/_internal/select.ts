import type { CatalogData } from "../../catalog.ts";
import type { Statement } from "../../types.ts";
import type { Question } from "../engine.ts";
import { chainOf, covers, placeOf } from "./data.ts";
import type { Given } from "./outcome.ts";
import { relatesTo } from "./relate.ts";

/** Who a call is for: the subject and the groups the application says it is in at that moment. */
export interface Member {
  subject: string;
  groups?: readonly string[];
}

/**
 * The statements an application hands over for a question: about the subject and its groups, then,
 * when only what is needed, live at the question's time, on the chain of its target and related to
 * its permission (Section 9 of the model).
 */
export function selectToAsk(
  data: CatalogData,
  statements: readonly Statement[],
  options: { member: Member; question: Question; at: number; given: Given },
): Statement[] {
  const about = applying(statements, options.member);
  if (options.given === "everything") return about;
  const chain = new Set(chainOf(options.question.place ?? "/"));
  const relates = relatesTo(data, options.question.permission);
  return about.filter(
    (statement) =>
      chain.has(placeOf(statement)) &&
      live(statement, options.at) &&
      (relates === undefined || relates(statement)),
  );
}

/**
 * The statements an application hands over to issue grants: about the subject and its groups, then,
 * when only what is needed, live at the time of issue and on the chain of a base or under one.
 */
export function selectToIssue(
  statements: readonly Statement[],
  options: { member: Member; bases?: readonly string[]; at: number; given: Given },
): Statement[] {
  const about = applying(statements, options.member);
  if (options.given === "everything") return about;
  const bases = options.bases === undefined || options.bases.length === 0 ? ["/"] : options.bases;
  return about.filter((statement) => {
    const place = placeOf(statement);
    return (
      live(statement, options.at) &&
      bases.some((base) => chainOf(base).includes(place) || covers(base, place))
    );
  });
}

function applying(statements: readonly Statement[], member: Member): Statement[] {
  const identifiers = new Set([member.subject, ...(member.groups ?? [])]);
  return statements.filter((statement) => identifiers.has(statement.subject));
}

function live(statement: Statement, at: number): boolean {
  const end: unknown = statement.expiresAt;
  return typeof end !== "number" || end > at;
}
