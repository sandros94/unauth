import { type RequestEvent, useRuntimeConfig } from "nuxt/server";
import { type PgliteDatabase, type PgliteTransaction, drizzle } from "drizzle-orm/pglite";
import { type Relations, relations } from "../db/relations";

export type Transaction = PgliteTransaction<Relations>;
export type Db = PgliteDatabase<Relations> | Transaction;

export const db: PgliteDatabase<Relations> = drizzle({
  connection: { dataDir: useRuntimeConfig().db.dataDir },
  relations,
});

export function useDB(event?: RequestEvent): Db {
  return event?.context.transaction ?? db;
}
