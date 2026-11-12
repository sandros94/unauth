import type { DatabaseSync } from "node:sqlite";

export function addUser(db: DatabaseSync, id: string): void {
  db.prepare("INSERT OR IGNORE INTO users (id) VALUES (?)").run(id);
}

export function userExists(db: DatabaseSync, id: string): boolean {
  return db.prepare("SELECT 1 FROM users WHERE id = ?").get(id) !== undefined;
}
