import { defineAuthz } from "unauth/z";

export const CAPABILITIES = {
  read: "site:read",
  edit_posts: "post:edit",
  edit_others_posts: "others-post:edit",
  edit_published_posts: "published-post:edit",
  edit_private_posts: "private-post:edit",
  delete_posts: "post:delete",
  delete_others_posts: "others-post:delete",
  delete_published_posts: "published-post:delete",
  delete_private_posts: "private-post:delete",
  read_private_posts: "private-post:read",
  publish_posts: "post:publish",
  create_users: "user:create",
  promote_users: "user:promote",
} as const;

export const authz = defineAuthz({
  permissions: Object.values(CAPABILITIES),
  places: false,
});

export type Permission = (typeof authz.catalog.data.permissions)[number];
