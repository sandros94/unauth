import type { Catalog, CatalogData } from "../../catalog.ts";
import type { StoredRole } from "../../types.ts";
import type { ClockOptions, Decision, Engine, IssueGrantsOptions, Question } from "../engine.ts";
import { type Context, fail, untouched } from "./outcome.ts";

/** Statements as a case hands them over: possibly not statements at all. */
export interface LooseRead {
  subject: string;
  statements: readonly unknown[];
  roles?: readonly StoredRole[];
}

/** The engine as the cases call it with data that may not be what its types say. */
export interface LooseEngine {
  defineCatalog(data: unknown): Catalog;
  ask(catalog: Catalog, read: LooseRead, question: Question, options?: ClockOptions): Decision;
  issueGrants(catalog: Catalog, read: LooseRead, options?: IssueGrantsOptions): unknown;
}

export function loose(engine: Engine): LooseEngine {
  return engine;
}

export function defineFor(engine: Engine, data: CatalogData, context: Context): Catalog {
  const result = untouched(context, data, (copy) => engine.defineCatalog(copy));
  if (!result.ok) return fail(context, "the catalog accepted", result.code);
  return result.value;
}
