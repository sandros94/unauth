import { placeChain, placeRange } from "../../../../src/z/place.ts";
import type { CountedDatabase, Params } from "./database.ts";

/** A row whose `place` covers one of the keys in `$chain`. */
export const ON_CHAIN = "place IN (SELECT value FROM json_each($chain))";

/** A row whose `place` lies under one of the keys whose ranges are in `$ranges`, byte by byte. */
export const UNDER = `EXISTS (
  SELECT 1 FROM json_each($ranges) AS range
  WHERE place > range.value ->> '$[0]' AND place < range.value ->> '$[1]'
)`;

/** `$chain` with the chain of every key of `on`, `$ranges` with the range of every key of `under`. */
export function placeParams(on: readonly string[], under: readonly string[]): Params {
  return { chain: chainParam(on), ranges: rangesParam(under) };
}

/** The distinct places of the statements under `key`. */
export function placesUnder(db: CountedDatabase, key: string): string[] {
  return places(db, `SELECT DISTINCT place FROM statements WHERE ${UNDER}`, {
    ranges: rangesParam([key]),
  });
}

/** The distinct places of the statements on the chain of `key`. */
export function placesOnChain(db: CountedDatabase, key: string): string[] {
  return places(db, `SELECT DISTINCT place FROM statements WHERE ${ON_CHAIN}`, {
    chain: chainParam([key]),
  });
}

function places(db: CountedDatabase, sql: string, params: Params): string[] {
  return db.read("places", sql, params).map((row) => String(row.place));
}

function chainParam(on: readonly string[]): string {
  return JSON.stringify([...new Set(on.flatMap((key) => placeChain(key)))]);
}

function rangesParam(under: readonly string[]): string {
  return JSON.stringify(
    under.map((key) => {
      const { after, before } = placeRange(key);
      return [after, before];
    }),
  );
}
