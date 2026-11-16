import { type H3Event, HTTPError } from "h3";
import { allowed } from "../../application/guard.ts";
import type { SignedIn } from "../../application/session.ts";
import { CAPABILITIES as cap, type Permission, authz } from "./authz.ts";
import type { Post } from "./posts.ts";

export type MetaCap = "edit_post" | "delete_post" | "read_post" | "publish_post";

const OWNED = {
  edit_post: {
    own: cap.edit_posts,
    published: cap.edit_published_posts,
    others: cap.edit_others_posts,
    private: cap.edit_private_posts,
  },
  delete_post: {
    own: cap.delete_posts,
    published: cap.delete_published_posts,
    others: cap.delete_others_posts,
    private: cap.delete_private_posts,
  },
} as const;

export function mapMetaCap(meta: MetaCap, user: string | undefined, post: Post): Permission[] {
  if (meta === "publish_post") return [cap.publish_posts];
  if (meta === "read_post") {
    if (post.status === "publish" || isAuthor(user, post)) return [cap.read];
    if (post.status === "private") return [cap.read_private_posts];
    return mapMetaCap("edit_post", user, post);
  }
  const primitives = OWNED[meta];
  const published = post.status === "publish" || post.status === "future";
  if (isAuthor(user, post)) return [published ? primitives.published : primitives.own];
  return [
    primitives.others,
    ...(published ? [primitives.published] : []),
    ...(post.status === "private" ? [primitives.private] : []),
  ];
}

export function userCan(event: H3Event, session: SignedIn, permission: Permission): boolean {
  return allowed(event, authz, session, { permission });
}

export function assertCan(
  event: H3Event,
  session: SignedIn,
  required: readonly Permission[],
): void {
  if (!required.every((permission) => userCan(event, session, permission))) {
    throw new HTTPError({ status: 403, message: "Sorry, you are not allowed to do that." });
  }
}

function isAuthor(user: string | undefined, post: Post): boolean {
  return post.author !== undefined && post.author === user;
}
