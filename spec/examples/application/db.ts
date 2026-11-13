import type { DatabaseSync } from "node:sqlite";
import type { H3Event } from "h3";

declare module "h3" {
  interface H3EventContext {
    db?: DatabaseSync;
  }
}

export function useDB(event?: H3Event): DatabaseSync {
  const db = event?.context.db;
  if (db === undefined) throw new Error("The request carries no database.");
  return db;
}

export function withTransaction<T>(event: H3Event, fn: (db: DatabaseSync) => T): T {
  const db = useDB(event);
  return transaction(db, () => fn(db));
}

export function transaction<T>(db: DatabaseSync, run: () => T): T {
  if (db.isTransaction) return run();
  db.exec("BEGIN IMMEDIATE");
  try {
    const result = run();
    db.exec("COMMIT");
    return result;
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}
