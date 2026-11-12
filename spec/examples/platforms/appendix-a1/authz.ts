import { defineAuthz } from "unauth/z";

export const authz = defineAuthz({
  permissions: ["post:read", "post:draft", "post:publish", "access:manage"],
  places: false,
});
