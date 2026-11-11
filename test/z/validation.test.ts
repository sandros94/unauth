import { describe, expect, it } from "vitest";
import { defineCatalog } from "../../src/z/catalog.ts";
import { checkChange, checkGenesis } from "../../src/z/change.ts";
import { decide } from "../../src/z/decide.ts";
import { issueGrants, readGrants } from "../../src/z/grants.ts";
import { placeChain, placeRange } from "../../src/z/place.ts";
import { cases } from "../../src/z/validation/cases.ts";
import {
  runCatalogCase,
  runGrantsCase,
  runPlaceCase,
  runScenario,
  validateEngine,
} from "../../src/z/validation/run.ts";
import type { Engine } from "../../src/z/validation/types.ts";

const engine: Engine = {
  defineCatalog,
  decide,
  issueGrants,
  readGrants,
  checkChange,
  checkGenesis,
  placeChain,
  placeRange,
};

describe("the engine against every case of the model", () => {
  it.each(cases.scenarios.map((scenario) => [scenario.id, scenario] as const))(
    "scenario %s",
    (_id, scenario) => {
      expect(() => runScenario(engine, scenario)).not.toThrow();
    },
  );

  it.each(cases.catalogCases.map((item) => [item.id, item] as const))("catalog %s", (_id, item) => {
    expect(() => runCatalogCase(engine, item)).not.toThrow();
  });

  it.each(cases.placeCases.map((item) => [item.id, item] as const))("key %s", (_id, item) => {
    expect(() => runPlaceCase(engine, item)).not.toThrow();
  });

  it.each(cases.grantsCases.map((item) => [item.id, item] as const))(
    "grants written by hand %s",
    (_id, item) => {
      expect(() => runGrantsCase(engine, item)).not.toThrow();
    },
  );

  it("reports nothing failed", () => {
    expect(validateEngine(engine, cases).failed).toEqual([]);
  });
});
