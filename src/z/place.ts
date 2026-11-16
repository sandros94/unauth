import { compiledOf } from "./_internal/compile.ts";
import { malformed } from "./_internal/errors.ts";
import { isToken } from "./_internal/grammar.ts";
import { assertKey, chainOf, isCanonicalKey, readKey, segmentKey } from "./_internal/keys.ts";
import { fits } from "./_internal/structure.ts";
import type { Catalog } from "./catalog.ts";

/** One step of a place: the kind of place and which one. */
export type PlaceSegment = readonly [level: string, value: string];

/**
 * Builds the key of a place from its segments, encoding each value: never join a key by hand. An
 * object names each level once, in order. A list is for a level that repeats, as folders do.
 *
 * @throws `ERR_AUTHZ_MALFORMED` for a level that is not a lowercase token or an empty value.
 *
 * @example
 * placeKey({ org: "acme", unit: "u7" }); // "/org=acme/unit=u7"
 * placeKey([["folder", "a"], ["folder", "b"]], { under: "/drive=d1" });
 */
export function placeKey(
  segments: Readonly<Record<string, string>> | readonly PlaceSegment[],
  options?: PlaceKeyOptions,
): string {
  let key = assertKey(options?.under ?? "/");
  const pairs: readonly unknown[] = Array.isArray(segments) ? segments : Object.entries(segments);
  for (const pair of pairs) {
    const [level, value]: readonly unknown[] = Array.isArray(pair) && pair.length === 2 ? pair : [];
    if (!isToken(level)) {
      throw malformed("The level of a place is not a token.", { what: "level", value: level });
    }
    key = segmentKey(key, level, value);
  }
  return key;
}

/** Options of {@link placeKey}. */
export interface PlaceKeyOptions {
  /** The key the segments continue from. @default "/" */
  under?: string;
}

/**
 * The segments of a key, values decoded, from the root down. The root has none.
 *
 * @throws `ERR_AUTHZ_MALFORMED` for a key that is not canonical.
 */
export function parsePlace(key: string): PlaceSegment[] {
  const segments = readKey(key);
  if (!segments)
    throw malformed("The key of the place is not canonical.", { what: "place", value: key });
  return segments;
}

/**
 * The keys of the places that cover a place: itself, then each one above it, up to the root.
 * A statement applies at a place when its own place is one of these, so they are the values to
 * put in the query that reads the statements for a question.
 *
 * @throws `ERR_AUTHZ_MALFORMED` for a key that is not canonical.
 *
 * @example
 * placeChain("/org=acme/unit=u7"); // ["/org=acme/unit=u7", "/org=acme", "/"]
 * // WHERE subject IN (...) AND place IN (...placeChain(place))
 */
export function placeChain(key: string): string[] {
  return chainOf(assertKey(key));
}

/**
 * The two keys every place under a place lies between, itself and its siblings left out, when keys
 * are compared byte by byte: the values for a range in the query that reads a whole subtree.
 *
 * @throws `ERR_AUTHZ_MALFORMED` for a key that is not canonical.
 *
 * @example
 * const { after, before } = placeRange("/org=acme");
 * // WHERE place > after AND place < before, under a byte-wise collation
 */
export function placeRange(key: string): { after: string; before: string } {
  const base = assertKey(key) === "/" ? "" : key;
  return { after: `${base}/`, before: `${base}0` };
}

/**
 * Whether `key` is a canonical key that fits the structure the catalog declares: the check to run
 * where the application builds a place from its own data, before it stores or asks about it. A
 * catalog that declares no structure holds every canonical key, one without places only the root.
 * Never throws: a key that is not canonical does not fit.
 *
 * @example
 * if (!placeFits(catalog, placeKey({ org, drive }))) throw notFound();
 */
export function placeFits(catalog: Catalog, key: string): boolean {
  return isCanonicalKey(key) && fits(compiledOf(catalog), key);
}
