import { type CacheDriver, loadCache } from "./load.ts";
import { type Fetch, isRecord, providerError, stringField } from "../http/shared.ts";
import { getObject } from "../http/json.ts";

/** What every {@link MetadataLoader} takes. */
export interface MetadataOptions {
  fetch: Fetch;
  now: () => number;
  /** Keep the document here instead of in memory. */
  cache?: CacheDriver;
  /** Fetch again even when the cached document is fresh. */
  force?: boolean;
}

/**
 * The well-known document of `key` (an issuer, an origin, a DID), kept ten minutes per key: in
 * memory per injected `fetch`, or in `options.cache`. Concurrent callers share one fetch; a failed
 * one is rethrown without a fetch for five seconds.
 */
export type MetadataLoader<T, TOptions extends MetadataOptions = MetadataOptions> = (
  key: string,
  options: TOptions,
) => Promise<T>;

/** How a {@link MetadataLoader} finds and reads its kind of document. */
export interface MetadataDefinition<T, TOptions extends MetadataOptions> {
  /** Names the cache in driver keys. */
  name: string;
  /** Names the document in error messages. */
  label: string;
  /** Where `key`'s document is. */
  url: (key: string, options: TOptions) => string;
  /**
   * What in `options` changes where `key`'s document is (a directory): documents are kept apart
   * per value, in memory and in a cache driver, so two configurations never read each other's.
   */
  partition?: (options: TOptions) => string;
  /**
   * The value `document` holds for `key`, as it arrived from its URL; throws
   * `ERR_AUTHN_PROVIDER_ERROR` on anything it would not have loaded.
   */
  parse: (document: unknown, key: string) => T;
  /**
   * The value a cache driver handed back for `key`, checked the same way; `parse` by default,
   * which fits a loader that keeps the document whole. A loader that keeps a projection of it
   * checks that projection here.
   */
  revive?: (value: unknown, key: string) => T;
  /** How old (ms) a held document must be before `force` may fetch it again; any age without one. */
  cooldown?: number;
}

/** A loader of one kind of well-known document, reading it through `getObject`. */
export function defineMetadataLoader<T, TOptions extends MetadataOptions = MetadataOptions>(
  definition: MetadataDefinition<T, TOptions>,
): MetadataLoader<T, TOptions> {
  const revive = definition.revive ?? definition.parse;
  const cache = loadCache<T>({
    name: definition.name,
    check: (value, entry) => revive(value, keyOf(entry)),
  });
  return (key, options) =>
    cache.get(
      entryOf(key, definition.partition?.(options)),
      () =>
        getObject(definition.url(key, options), {
          fetch: options.fetch,
          label: definition.label,
        }).then((document) => definition.parse(document, key)),
      {
        now: options.now,
        force: options.force,
        cooldown: definition.cooldown,
        scope: options.fetch,
        driver: options.cache,
      },
    );
}

/** `document` once it is a JSON object; `ERR_AUTHN_PROVIDER_ERROR` otherwise. */
export function assertDocument(
  document: unknown,
  context: { url: string; label: string },
): Record<string, unknown> {
  if (!isRecord(document)) {
    throw providerError(`The ${context.label} at ${context.url} is not a JSON object.`, {
      reason: "malformed",
    });
  }
  return document;
}

/** `document` once it is a JSON object whose `issuer` is exactly `issuer`; `ERR_AUTHN_PROVIDER_ERROR` otherwise. */
export function assertIssuerDocument(
  document: unknown,
  context: { issuer: string; url: string; label: string },
): Record<string, unknown> {
  const object = assertDocument(document, context);
  if (object.issuer !== context.issuer) {
    throw providerError(
      `The ${context.label} at ${context.url} names the issuer ${JSON.stringify(object.issuer)} instead of ${JSON.stringify(context.issuer)}.`,
      { reason: "malformed" },
    );
  }
  return object;
}

/** The non-empty string member `name` of `document`; `ERR_AUTHN_PROVIDER_ERROR` without one. */
export function requiredMember(
  document: Record<string, unknown>,
  name: string,
  context: { url: string; label: string },
): string {
  const value = stringField(document, name);
  if (value === undefined) {
    throw providerError(`The ${context.label} at ${context.url} has no "${name}".`, {
      reason: "malformed",
    });
  }
  return value;
}

/** Keeps a partition and a key apart in one cache entry name; neither carries a newline. */
const PARTITION_SEPARATOR = "\n";

function entryOf(key: string, partition: string | undefined): string {
  return partition === undefined ? key : `${partition}${PARTITION_SEPARATOR}${key}`;
}

/** The key of a cache entry name, its partition dropped. */
function keyOf(entry: string): string {
  const at = entry.indexOf(PARTITION_SEPARATOR);
  return at === -1 ? entry : entry.slice(at + 1);
}
