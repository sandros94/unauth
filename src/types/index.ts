export type MaybePromise<T> = T | Promise<T>;

export type Require<T extends object, K extends keyof T> = ParseType<T & Required<Pick<T, K>>>;

export type ParseType<T> = {
  [K in keyof T]: T[K];
} & {};
