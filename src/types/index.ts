export type MaybePromise<T> = T | Promise<T>;

export type ParseType<T> = {
  [K in keyof T]: T[K];
} & {};

type UnionToIntersection<U> = (U extends any ? (k: U) => void : never) extends (
  k: infer I,
) => void
  ? I
  : never;

type RequirePath<T, P extends string> = P extends `${infer Head}.${infer Rest}`
  ? Head extends keyof T
    ? Omit<T, Head> & {
        [K in Head]-?: RequirePath<
          NonNullable<T[Head]> extends object ? NonNullable<T[Head]> : T[Head],
          Rest
        >;
      }
    : T
  : P extends keyof T
    ? ParseType<T & Required<Pick<T, P>>>
    : T;

/**
 * Require<T, K>
 * - K may be a single key or a union of keys
 * - Keys may use dot-notation to indicate nested properties, e.g. "a.b.c"
 */
export type Require<
  T extends object,
  K extends keyof T | (string & {}),
> = ParseType<
  UnionToIntersection<
    K extends any ? RequirePath<T, Extract<K, string>> : never
  >
>;
