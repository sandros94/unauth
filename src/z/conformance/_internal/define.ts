import type { Catalog, CatalogData } from "../../catalog.ts";
import type { Engine } from "../engine.ts";
import { type Context, fail, untouched } from "./outcome.ts";

/** The engine as the cases call it with data that may not be what its types say. */
export interface LooseEngine {
  defineCatalog(data: unknown): Catalog;
}

export function loose(engine: Engine): LooseEngine {
  return engine;
}

export function defineFor(engine: Engine, data: CatalogData, context: Context): Catalog {
  const result = untouched(context, data, (copy) => engine.defineCatalog(copy));
  if (!result.ok) return fail(context, "the catalog accepted", result.code);
  return result.value;
}
