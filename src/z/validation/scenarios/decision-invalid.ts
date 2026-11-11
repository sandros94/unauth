import type { CatalogData } from "../../catalog.ts";
import type { Scenario } from "../types.ts";
import { MONDAY, allow, ask, assign } from "./_internal/scenario-steps.ts";

const NEWS = "/site=blog/section=news";

const posts: CatalogData = {
  permissions: ["post:read", "post:edit", "post:approve"],
  presets: { editor: ["post:read", "post:edit"] },
  places: { "/": ["site"], "site": ["section"] },
};

export const decisionInvalidScenarios: readonly Scenario[] = [
  {
    id: "decision/invalid-questions",
    title: "Questions an application builds wrong are refused, also for the owner",
    proves: [],
    catalog: posts,
    statements: [assign("eva", "editor", "/site=blog"), allow("owner", "*")],
    steps: [
      ask(MONDAY, { subject: "eva", permission: "", place: NEWS }, "ERR_AUTHZ_QUESTION_INVALID", {
        issuedAt: MONDAY,
      }),
      ask(
        MONDAY,
        { subject: "eva", permission: "post:*", place: NEWS },
        "ERR_AUTHZ_QUESTION_INVALID",
        { issuedAt: MONDAY },
      ),
      ask(MONDAY, { subject: "eva", permission: "*", place: NEWS }, "ERR_AUTHZ_QUESTION_INVALID"),
      ask(
        MONDAY,
        { subject: "eva", permission: "post:delete", place: NEWS },
        "ERR_AUTHZ_PERMISSION_UNKNOWN",
        { issuedAt: MONDAY },
      ),
      ask(MONDAY, { subject: "eva", permission: "Post:edit", place: NEWS }, "ERR_AUTHZ_MALFORMED", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "owner", permission: "" }, "ERR_AUTHZ_QUESTION_INVALID"),
      ask(MONDAY, { subject: "owner", permission: "post:delete" }, "ERR_AUTHZ_PERMISSION_UNKNOWN"),
      ask(MONDAY, { subject: "owner", permission: "*:*" }, "ERR_AUTHZ_MALFORMED"),
      ask(MONDAY, { subject: "owner", permission: "*" }, "ERR_AUTHZ_QUESTION_INVALID", {
        issuedAt: MONDAY,
      }),
    ],
  },
];
