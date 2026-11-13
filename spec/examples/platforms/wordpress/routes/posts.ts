import type { DatabaseSync } from "node:sqlite";
import { type H3, type H3Event, HTTPError } from "h3";
import { useDB } from "../../../application/db.ts";
import { param, readBody, textOf } from "../../../application/http.ts";
import { findAuthSession, requireAuthSession } from "../../../application/session.ts";
import { CAPABILITIES as cap, authz } from "../authz.ts";
import { assertCan, mapMetaCap, userCan } from "../capabilities.ts";
import {
  type Post,
  deletePost,
  findPost,
  insertPost,
  isStatus,
  listPosts,
  updatePost,
} from "../posts.ts";

export function postRoutes(app: H3): void {
  app.get("/posts", async (event) => {
    const session = await findAuthSession(event, authz);
    const allPrivate = session !== undefined && userCan(event, session, cap.read_private_posts);
    return listPosts(useDB(event), { user: session?.subject, allPrivate });
  });

  app.get("/posts/:id", async (event) => {
    const post = postOf(useDB(event), event);
    if (post.status === "publish") return post;
    const session = await requireAuthSession(event, authz);
    assertCan(event, session, mapMetaCap("read_post", session.subject, post));
    return post;
  });

  app.post("/posts", async (event) => {
    const session = await requireAuthSession(event, authz);
    assertCan(event, session, [cap.edit_posts]);
    const title = textOf(await readBody(event), "title");
    event.res.status = 201;
    return insertPost(useDB(event), { author: session.subject, status: "draft", title });
  });

  app.put("/posts/:id", async (event) => {
    const post = postOf(useDB(event), event);
    const session = await requireAuthSession(event, authz);
    const body = await readBody(event);
    const status = body.status ?? post.status;
    if (!isStatus(status)) throw new HTTPError({ status: 400, message: "No such status." });
    const publishing = status === "publish" && post.status !== "publish";
    assertCan(event, session, [
      ...mapMetaCap("edit_post", session.subject, post),
      ...(publishing ? mapMetaCap("publish_post", session.subject, post) : []),
    ]);
    const title = body.title === undefined ? post.title : textOf(body, "title");
    const updated = { ...post, status, title };
    updatePost(useDB(event), updated);
    return updated;
  });

  app.delete("/posts/:id", async (event) => {
    const post = postOf(useDB(event), event);
    const session = await requireAuthSession(event, authz);
    assertCan(event, session, mapMetaCap("delete_post", session.subject, post));
    deletePost(useDB(event), post.id);
    return { id: post.id };
  });
}

function postOf(db: DatabaseSync, event: H3Event): Post {
  const post = findPost(db, Number(param(event, "id")));
  if (post === undefined) throw new HTTPError({ status: 404, message: "No such post." });
  return post;
}
