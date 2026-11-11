import { malformed } from "./errors.ts";
import { isToken } from "./grammar.ts";

/** One segment of a key, its value decoded. */
export type KeySegment = readonly [level: string, value: string];

/**
 * The decoded segments of `key` from the root down, `[]` for the root, or `undefined` when `key`
 * is not canonical: the grammar, percent-encoding in uppercase only for an octet that may not be
 * written literally, and the decoded octets of each value valid UTF-8.
 */
export function readKey(key: unknown): KeySegment[] | undefined {
  if (typeof key !== "string" || !key.startsWith("/")) return undefined;
  if (key === "/") return [];
  const segments: KeySegment[] = [];
  for (const part of key.slice(1).split("/")) {
    const equals = part.indexOf("=");
    if (equals < 0) return undefined;
    const level = part.slice(0, equals);
    if (!isToken(level)) return undefined;
    const value = decodeValue(part.slice(equals + 1));
    if (value === undefined) return undefined;
    segments.push([level, value]);
  }
  return segments;
}

/** Whether `key` is a canonical key. */
export function isCanonicalKey(key: unknown): key is string {
  return readKey(key) !== undefined;
}

/** `key` when it is canonical, else `ERR_AUTHZ_MALFORMED`. Never repaired. */
export function assertKey(key: unknown): string {
  if (!isCanonicalKey(key)) {
    throw malformed("The key of the place is not canonical.", { what: "place", value: key });
  }
  return key;
}

/** The key of a statement's or a question's place: `"/"` when absent. */
export function placeOf(place: string | undefined): string {
  return place ?? "/";
}

/** The levels of a canonical key, from the root down. */
export function levelsOf(key: string): string[] {
  if (key === "/") return [];
  return key
    .slice(1)
    .split("/")
    .map((part) => part.slice(0, part.indexOf("=")));
}

/**
 * The canonical spelling of one segment's value: its UTF-8 octets, each one `literal` does not
 * allow percent-encoded in uppercase. `ERR_AUTHZ_MALFORMED` for a value that is empty, not a
 * string, or not a sequence of Unicode scalar values.
 */
export function encodeValue(value: unknown): string {
  if (typeof value !== "string" || value === "" || LONE_SURROGATE.test(value)) {
    throw malformed("The value of a place is not usable.", { what: "value", value });
  }
  let out = "";
  for (const octet of encoder.encode(value)) {
    out += LITERAL[octet] ? String.fromCharCode(octet) : `%${HEX[octet >> 4]}${HEX[octet & 15]}`;
  }
  return out;
}

/**
 * The key of the segment `level=value` under the canonical key `under`, the value encoded with
 * {@link encodeValue}. `level` must be a token.
 */
export function segmentKey(under: string, level: string, value: unknown): string {
  return `${under === "/" ? "" : under}/${level}=${encodeValue(value)}`;
}

/** The chain of a canonical key: itself, then each place above it, ending with `"/"`. */
export function chainOf(key: string): string[] {
  const chain = [key];
  let current = key;
  while (current !== "/") {
    current = current.slice(0, current.lastIndexOf("/")) || "/";
    chain.push(current);
  }
  return chain;
}

/** Whether a statement at the canonical key `outer` applies at the canonical key `inner`. */
export function covers(outer: string, inner: string): boolean {
  return outer === "/" || inner === outer || inner.startsWith(`${outer}/`);
}

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const HEX = "0123456789ABCDEF";
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const LITERAL: readonly boolean[] = Array.from({ length: 256 }, (_, octet) =>
  /^[A-Za-z0-9\-._~!$&'()*+,;=:@]$/.test(String.fromCharCode(octet)),
);

function decodeValue(text: string): string | undefined {
  if (text === "") return undefined;
  const octets: number[] = [];
  for (let index = 0; index < text.length; index++) {
    const code = text.charCodeAt(index);
    if (code === 0x25) {
      const octet =
        upperHex(text.charCodeAt(index + 1)) * 16 + upperHex(text.charCodeAt(index + 2));
      if (!(octet >= 0) || LITERAL[octet]) return undefined;
      octets.push(octet);
      index += 2;
    } else if (code < 0x80 && LITERAL[code]) {
      octets.push(code);
    } else {
      return undefined;
    }
  }
  try {
    return decoder.decode(new Uint8Array(octets));
  } catch {
    return undefined;
  }
}

function upperHex(code: number): number {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;
  if (code >= 0x41 && code <= 0x46) return code - 0x37;
  return Number.NaN;
}
