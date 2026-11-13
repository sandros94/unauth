import { base64UrlStringify } from "unjwt/utils";
import type { PlainCatalogData } from "./compiled.ts";
import { compareBytes, sortedUnique } from "./grammar.ts";
import { sha256 } from "./sha256.ts";

/**
 * The two texts the fingerprint hashes, one per segment: the catalog data restricted to
 * `permissions`, `implies` and `places`, then to `presets`. Every member that declares nothing is
 * left out at every depth, every list sorted by bytes with each value once, every object's members
 * sorted by name, written as JSON with no whitespace, `{}` when nothing is left. `places: false`
 * declares that there are no places and a preset with no entries declares a role, so both are kept.
 */
export function canonicalSegments(data: PlainCatalogData): [declares: string, presets: string] {
  const declares: [string, string][] = [];
  const permissions = writeList(data.permissions);
  if (permissions) declares.push(["permissions", permissions]);
  const implies = data.implies && writeLists(data.implies, false);
  if (implies) declares.push(["implies", implies]);
  if (data.places === false) declares.push(["places", "false"]);
  else if (data.places) {
    const places = writeLists(data.places, false);
    if (places) declares.push(["places", places]);
  }
  const presets = data.presets && writeLists(data.presets, true);
  return [writeObject(declares) ?? "{}", presets ? `{"presets":${presets}}` : "{}"];
}

/**
 * The fingerprint of catalog data, `<declares>.<presets>`, 23 characters: per text of
 * {@link canonicalSegments}, the first 8 octets of SHA-256 over its UTF-8 octets, base64url
 * without padding.
 */
export function catalogFingerprint(data: PlainCatalogData): string {
  return canonicalSegments(data).map(segmentOf).join(".");
}

function segmentOf(text: string): string {
  return base64UrlStringify(sha256(new TextEncoder().encode(text)).subarray(0, 8));
}

function writeList(values: readonly string[]): string | undefined {
  if (values.length === 0) return undefined;
  return JSON.stringify(sortedUnique(values));
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
