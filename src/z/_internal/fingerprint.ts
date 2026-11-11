import { base64UrlStringify } from "unjwt/utils";
import type { PlainCatalogData } from "./catalog-data.ts";
import { compareBytes, sortedUnique } from "./grammar.ts";
import { sha256 } from "./sha256.ts";

/**
 * The text the fingerprint hashes: the catalog data with every member that declares nothing left
 * out at every depth, every list sorted by bytes with each value once, every object's members
 * sorted by name, written as JSON with no whitespace. `places: false` declares that there are no
 * places and a preset with no entries declares a role, so both are kept.
 */
export function canonicalCatalog(data: PlainCatalogData): string {
  const members: [string, string][] = [];
  const permissions = writeList(data.permissions);
  if (permissions) members.push(["permissions", permissions]);
  const implies = data.implies && writeLists(data.implies, false);
  if (implies) members.push(["implies", implies]);
  const presets = data.presets && writeLists(data.presets, true);
  if (presets) members.push(["presets", presets]);
  if (data.places === false) members.push(["places", "false"]);
  else if (data.places) {
    const places = writeLists(data.places, false);
    if (places) members.push(["places", places]);
  }
  if (data.manager !== undefined) members.push(["manager", JSON.stringify(data.manager)]);
  if (data.assigner) {
    const assigner = writeObject(
      Object.entries(data.assigner).map(([name, value]) => [name, JSON.stringify(value)]),
    );
    if (assigner) members.push(["assigner", assigner]);
  }
  return writeObject(members) ?? "{}";
}

/**
 * The fingerprint of catalog data: SHA-256 of the UTF-8 octets of {@link canonicalCatalog},
 * base64url without padding, 43 characters.
 */
export function catalogFingerprint(data: PlainCatalogData): string {
  return base64UrlStringify(sha256(new TextEncoder().encode(canonicalCatalog(data))));
}

function writeList(values: readonly string[]): string | undefined {
  if (values.length === 0) return undefined;
  return `[${sortedUnique(values)
    .map((value) => JSON.stringify(value))
    .join(",")}]`;
}

function writeLists(
  lists: Readonly<Record<string, readonly string[]>>,
  keepEmpty: boolean,
): string | undefined {
  const members: [string, string][] = [];
  for (const [name, values] of Object.entries(lists)) {
    const written = writeList(values) ?? (keepEmpty ? "[]" : undefined);
    if (written) members.push([name, written]);
  }
  return writeObject(members);
}

function writeObject(members: [string, string][]): string | undefined {
  if (members.length === 0) return undefined;
  members.sort(([a], [b]) => compareBytes(a, b));
  return `{${members.map(([name, value]) => `${JSON.stringify(name)}:${value}`).join(",")}}`;
}
