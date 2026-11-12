import type { DatabaseSync } from "node:sqlite";
import { type Row, integer, text } from "../../storage/rows.ts";

export const STATUSES = ["publish", "future", "draft", "pending", "private"] as const;

export type Status = (typeof STATUSES)[number];

export interface Post {
  id: number;
  author: string | undefined;
  status: Status;
  title: string;
}

export function isStatus(value: unknown): value is Status {
  return STATUSES.some((status) => status === value);
}

export function findPost(db: DatabaseSync, id: number): Post | undefined {
  const row = db.prepare("SELECT id, author, status, title FROM posts WHERE id = ?").get(id);
  return row === undefined ? undefined : postOf(row);
}

export function listPosts(
  db: DatabaseSync,
  reader: { user: string | undefined; allPrivate: boolean },
): Post[] {
  return db
    .prepare(
      `SELECT id, author, status, title FROM posts
       WHERE status = 'publish'
          OR (status = 'private' AND $user IS NOT NULL AND ($all = 1 OR author = $user))
       ORDER BY id`,
    )
    .all({ user: reader.user ?? null, all: reader.allPrivate ? 1 : 0 })
    .map(postOf);
}

export function insertPost(db: DatabaseSync, post: Omit<Post, "id">): Post {
  const { lastInsertRowid } = db
    .prepare("INSERT INTO posts (author, status, title) VALUES (?, ?, ?)")
    .run(post.author ?? null, post.status, post.title);
  return { id: Number(lastInsertRowid), ...post };
}

export function updatePost(db: DatabaseSync, post: Post): void {
  db.prepare("UPDATE posts SET status = ?, title = ? WHERE id = ?").run(
    post.status,
    post.title,
    post.id,
  );
}

export function deletePost(db: DatabaseSync, id: number): void {
  db.prepare("DELETE FROM posts WHERE id = ?").run(id);
}

function postOf(row: Row): Post {
  const status = text(row, "status");
  const author = row.author;
  if (!isStatus(status)) throw new TypeError(`Unknown post status ${status}.`);
  return {
    id: integer(row, "id") ?? 0,
    author: typeof author === "string" ? author : undefined,
    status,
    title: text(row, "title"),
  };
}
