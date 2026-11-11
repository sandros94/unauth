import { describe, expect, it } from "vitest";
import { defineCatalog } from "../../src/z/catalog.ts";
import { checkChange } from "../../src/z/change.ts";
import type { Statement } from "../../src/z/types.ts";
import { refused } from "./_expect.ts";

const catalog = defineCatalog({
  permissions: ["report:read", "access:manage"],
  presets: { owner: ["*"] },
  manager: "access:manage",
});

const NOW = 1_794_214_800;
const DAY = 86_400;
const now = (): number => NOW * 1000;

const ana: Statement = { kind: "allow", subject: "ana", value: "*" };
const deploy: Statement = { kind: "allow", subject: "deploy", value: "*" };
const vic: Statement = { kind: "assign", subject: "vic", value: "owner" };
const ending: Statement = { ...deploy, expiresAt: NOW + DAY };

describe("putting an end on a permanent manager's allow", () => {
  it("is refused to an owner by role, who could not remove it either", () => {
    const options = { author: "vic", statements: [vic], managers: [ana, deploy], now };
    const removal = refused(() =>
      checkChange(catalog, { action: "remove", statement: deploy }, options),
    );
    expect(removal.cause).toEqual({ reasons: ["not-held"] });
    const placement = refused(() =>
      checkChange(catalog, { action: "place", statement: ending }, options),
    );
    expect(placement.cause).toEqual({ reasons: ["not-held"] });
  });

  it("is accepted from another permanent manager while one stays", () => {
    const options = { author: "ana", statements: [ana], managers: [ana, deploy], now };
    expect(() =>
      checkChange(catalog, { action: "place", statement: ending }, options),
    ).not.toThrow();
  });

  it("names both reasons when the owner by role would also leave the root without one", () => {
    const options = { author: "vic", statements: [vic], managers: [deploy], now };
    const placement = refused(() =>
      checkChange(catalog, { action: "place", statement: ending }, options),
    );
    expect(placement.cause).toEqual({ reasons: ["not-held", "last-manager"] });
  });

  it("lets an owner by role give a temporary allow of everything to someone who holds no permanent one", () => {
    const temp: Statement = {
      kind: "allow",
      subject: "contractor",
      value: "*",
      expiresAt: NOW + DAY,
    };
    const options = { author: "vic", statements: [vic], managers: [ana, deploy], now };
    expect(() => checkChange(catalog, { action: "place", statement: temp }, options)).not.toThrow();
  });
});
