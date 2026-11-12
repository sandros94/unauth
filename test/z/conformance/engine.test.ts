import { describe, expect, it } from "vitest";
import { defineCatalog } from "../../../src/z/catalog.ts";
import { ask } from "../../../src/z/ask.ts";
import { could, issueGrants } from "../../../src/z/grants.ts";
import { placeChain, placeRange } from "../../../src/z/place.ts";
import { validateRole, validateStatement } from "../../../src/z/validate.ts";
import { cases } from "../../../src/z/conformance/cases.ts";
import {
  runCatalogCase,
  runConformance,
  runGrantsCase,
  runPlaceCase,
  runRoleCase,
  runScenario,
  runStatementCase,
} from "../../../src/z/conformance/run.ts";
import type { Engine } from "../../../src/z/conformance/engine.ts";

const engine: Engine = {
  defineCatalog,
  ask,
  could,
  issueGrants,
  placeChain,
  placeRange,
  validateStatement,
  validateRole,
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

  it.each(cases.statementCases.map((item) => [item.id, item] as const))(
    "validating %s",
    (_id, item) => {
      expect(() => runStatementCase(engine, item)).not.toThrow();
    },
  );

  it.each(cases.roleCases.map((item) => [item.id, item] as const))("validating %s", (_id, item) => {
    expect(() => runRoleCase(engine, item)).not.toThrow();
  });

  it("reports nothing failed", () => {
    expect(runConformance(engine, cases).failed).toEqual([]);
  });
});
