/// <reference types="node" />
import { DatabaseSync, type SQLInputValue, type SQLOutputValue } from "node:sqlite";

export type Row = Record<string, SQLOutputValue>;
export type Params = Record<string, SQLInputValue>;

/** One statement executed against the database. */
export interface Trip {
  kind: "read" | "write";
  label: string;
  /** Rows a read returned, rows a write changed. */
  rows: number;
  /** The rows a read returned, as JSON. Zero for a write. */
  bytes: number;
  /** The transaction it ran in, absent outside one. */
  transaction?: number;
}

/** How a transaction ended. */
export interface Ended {
  transaction: number;
  outcome: "commit" | "rollback";
}

/** What happened on one connection while a function ran. */
export interface Measured<T> {
  result: T;
  trips: Trip[];
  ended: Ended[];
}

/**
 * A connection to an in-memory database whose every statement goes through {@link read} or
 * {@link write} and is counted there. The underlying handle is private, so nothing reaches the
 * database without a trip on the log.
 */
export class CountedDatabase {
  readonly #db: DatabaseSync;
  readonly #name: string;
  readonly #trips: Trip[] = [];
  readonly #ended: Ended[] = [];
  #open: number | undefined;
  #next = 1;

  private constructor(name: string) {
    this.#name = name;
    this.#db = new DatabaseSync(new URL(`file:${name}?mode=memory&cache=shared`));
  }

  /** A new, empty database. */
  static create(): CountedDatabase {
    return new CountedDatabase(`z-${crypto.randomUUID()}`);
  }

  /** A second connection to the same database, with a log of its own. */
  connect(): CountedDatabase {
    return new CountedDatabase(this.#name);
  }

  read(label: string, sql: string, params: Params = {}): Row[] {
    const rows = this.#db.prepare(sql).all(params);
    this.#trips.push({
      kind: "read",
      label,
      rows: rows.length,
      bytes: JSON.stringify(rows).length,
      ...(this.#open !== undefined && { transaction: this.#open }),
    });
    return rows;
  }

  write(label: string, sql: string, params: Params = {}): number {
    const { changes } = this.#db.prepare(sql).run(params);
    const rows = Number(changes);
    this.#trips.push({
      kind: "write",
      label,
      rows,
      bytes: 0,
      ...(this.#open !== undefined && { transaction: this.#open }),
    });
    return rows;
  }

  /** Schema statements, logged as one write. */
  define(label: string, sql: string): void {
    this.#db.exec(sql);
    this.#trips.push({ kind: "write", label, rows: 0, bytes: 0 });
  }

  /** Runs `run` in one immediate transaction, committed when it returns, rolled back when it throws. */
  transaction<T>(run: () => T): T {
    const id = this.#next++;
    this.#db.exec("BEGIN IMMEDIATE");
    this.#open = id;
    try {
      const result = run();
      this.#db.exec("COMMIT");
      this.#ended.push({ transaction: id, outcome: "commit" });
      return result;
    } catch (error) {
      this.#db.exec("ROLLBACK");
      this.#ended.push({ transaction: id, outcome: "rollback" });
      throw error;
    } finally {
      this.#open = undefined;
    }
  }

  /** The trips and transaction endings logged while `run` ran. */
  measure<T>(run: () => T): Measured<T> {
    const trips = this.#trips.length;
    const ended = this.#ended.length;
    const result = run();
    return { result, trips: this.#trips.slice(trips), ended: this.#ended.slice(ended) };
  }

  close(): void {
    this.#db.close();
  }
}
