import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { sqlAgreed, sqlReached } from "../check.ts";
import { type Caller, signedIn, visitor } from "../client.ts";
import { type WordPress, createWordPress } from "./app.ts";
import { CAPABILITIES as cap } from "./authz.ts";
import { addCap, addRole, resetRole } from "./roles.ts";
import { seed } from "./seed.ts";

vi.mock(import("../../storage/ask.ts"), async (original) =>
  (await import("../check.ts")).againstAsk(await original()),
);

let wordpress: WordPress;
const as = (user: string): Promise<Caller> => signedIn(wordpress.app, user);
const idOf = (post: unknown): number => {
  if (typeof post === "object" && post !== null && "id" in post && typeof post.id === "number") {
    return post.id;
  }
  throw new TypeError("The reply holds no post.");
};
const listed = async (caller: Caller): Promise<unknown> => {
  const { body } = await caller.get("/posts");
  return Array.isArray(body) ? body.map(idOf) : body;
};

beforeAll(() => {
  wordpress = createWordPress();
  seed(wordpress.db);
});

afterEach(sqlAgreed);
afterAll(sqlReached);

describe("WordPress: reading content", () => {
  it("a published post is served to everyone, with no capability check", async () => {
    expect(await visitor(wordpress.app).get("/posts/1")).toEqual({
      status: 200,
      body: { id: 1, author: "arthur", status: "publish", title: "Hello world" },
    });
  });

  it("a logged-out visitor lists published posts only: private posts are added for logged-in users", async () => {
    expect(await listed(visitor(wordpress.app))).toEqual([1, 5, 10]);
    expect(await listed(await as("sam"))).toEqual([1, 5, 10]);
  });

  it("a logged-out visitor is not shown an unpublished or private post", async () => {
    expect((await visitor(wordpress.app).get("/posts/2")).status).toBe(401);
    expect((await visitor(wordpress.app).get("/posts/3")).status).toBe(401);
  });

  it("without read_private_posts a list adds only the user's own private posts", async () => {
    expect(await listed(await as("arthur"))).toEqual([1, 3, 5, 10]);
  });

  it("an editor holds read_private_posts and lists every private post", async () => {
    expect(await listed(await as("edgar"))).toEqual([1, 3, 5, 7, 10]);
  });

  it("read_post: the author reads their own private post, anyone else needs read_private_posts", async () => {
    const arthur = await as("arthur");
    expect((await arthur.get("/posts/3")).status).toBe(200);
    expect((await arthur.get("/posts/7")).status).toBe(403);
    expect((await (await as("sam")).get("/posts/3")).status).toBe(403);
    expect((await (await as("edgar")).get("/posts/7")).status).toBe(200);
  });

  it("read_post of a draft is edit_post: its author and editors see it, a subscriber does not", async () => {
    expect((await (await as("arthur")).get("/posts/2")).status).toBe(200);
    expect((await (await as("edgar")).get("/posts/2")).status).toBe(200);
    const refused = await (await as("sam")).get("/posts/2");
    expect(refused).toEqual({
      status: 403,
      body: expect.objectContaining({ message: "Sorry, you are not allowed to do that." }),
    });
  });
});

describe("WordPress: writing posts", () => {
  it("creating a post takes edit_posts: a contributor may, a subscriber may not", async () => {
    const created = await (await as("connie")).post("/posts", { title: "Connie's notes" });
    expect(created).toEqual({
      status: 201,
      body: { id: 11, author: "connie", status: "draft", title: "Connie's notes" },
    });
    expect((await (await as("sam")).post("/posts", { title: "Sam's post" })).status).toBe(403);
  });

  it("a contributor edits her own unpublished post (edit_posts) and nobody else's (edit_others_posts)", async () => {
    const connie = await as("connie");
    expect((await connie.put("/posts/6", { title: "Connie's pitch, revised" })).status).toBe(200);
    expect((await connie.put("/posts/4", { title: "Otto's draft, by Connie" })).status).toBe(403);
  });

  it("publishing takes publish_posts: a contributor cannot, an author can", async () => {
    expect((await (await as("connie")).put("/posts/6", { status: "publish" })).status).toBe(403);
    const published = await (await as("arthur")).put("/posts/2", { status: "publish" });
    expect(published.body).toEqual(expect.objectContaining({ id: 2, status: "publish" }));
  });

  it("an author edits their own published post (edit_published_posts) and not someone else's post", async () => {
    const arthur = await as("arthur");
    expect((await arthur.put("/posts/1", { title: "Hello again" })).status).toBe(200);
    expect((await arthur.put("/posts/5", { title: "Otto's story, by Arthur" })).status).toBe(403);
    expect((await arthur.put("/posts/4", { title: "Otto's draft, by Arthur" })).status).toBe(403);
  });

  it("an editor edits and publishes other people's posts: edit_others_posts, and edit_published_posts once published", async () => {
    const edgar = await as("edgar");
    expect((await edgar.put("/posts/6", { status: "publish" })).status).toBe(200);
    expect((await edgar.put("/posts/5", { title: "Otto's story, edited" })).status).toBe(200);
  });

  it("once her post is published, a contributor lacks edit_published_posts and can no longer edit it", async () => {
    const reply = await (await as("connie")).put("/posts/6", { title: "Too late" });
    expect(reply.status).toBe(403);
  });

  it("a contributor deletes her own draft (delete_posts) and not someone else's (delete_others_posts)", async () => {
    const connie = await as("connie");
    expect(await connie.delete("/posts/11")).toEqual({ status: 200, body: { id: 11 } });
    expect((await connie.delete("/posts/4")).status).toBe(403);
  });

  it("on a single site an administrator holds every capability", async () => {
    const adele = await as("adele");
    expect((await adele.put("/posts/7", { title: "Otto's notes, reviewed" })).status).toBe(200);
    expect((await adele.delete("/posts/5")).status).toBe(200);
  });
});

describe("WordPress: capabilities set on the user", () => {
  it("a capability set to false on the user overrides what the role gives", async () => {
    const dora = await as("dora");
    expect((await dora.put("/posts/8", { status: "publish" })).status).toBe(403);
    expect((await dora.put("/posts/10", { title: "Dora's story, revised" })).status).toBe(200);
  });

  it("a capability granted to the user adds to what the role gives", async () => {
    const reply = await (await as("cora")).put("/posts/9", { status: "publish" });
    expect(reply.body).toEqual(expect.objectContaining({ id: 9, status: "publish" }));
  });
});

describe("WordPress: users and roles", () => {
  it("a new user gets the default role, subscriber", async () => {
    const created = await (await as("adele")).post("/users", { user: "nora" });
    expect(created).toEqual({ status: 201, body: { user: "nora", role: "subscriber" } });
    const nora = await as("nora");
    expect((await nora.post("/posts", { title: "Nora's post" })).status).toBe(403);
    expect(await listed(nora)).toEqual([1, 2, 6, 9, 10]);
  });

  it("creating users takes create_users: an editor cannot", async () => {
    expect((await (await as("edgar")).post("/users", { user: "ned" })).status).toBe(403);
  });

  it("Change role to…: promote_users lets an administrator give a user another role", async () => {
    const changed = await (await as("adele")).put("/users/sam/role", { role: "author" });
    expect(changed).toEqual({ status: 200, body: { user: "sam", role: "author" } });
    const sam = await as("sam");
    const created = await sam.post("/posts", { title: "Sam's first post" });
    expect(created.status).toBe(201);
    const id = idOf(created.body);
    expect((await sam.put(`/posts/${id}`, { status: "publish" })).status).toBe(200);
  });

  it("without promote_users an editor changes nobody's role", async () => {
    const refused = await (await as("edgar")).put("/users/connie/role", { role: "editor" });
    expect(refused.status).toBe(403);
  });

  it("a role outside the editable roles is refused: 'Sorry, you are not allowed to give users that role.'", async () => {
    const refused = await (await as("adele")).put("/users/sam/role", { role: "overlord" });
    expect(refused).toEqual({
      status: 400,
      body: expect.objectContaining({
        message: "Sorry, you are not allowed to give users that role.",
        data: {
          issues: [expect.objectContaining({ code: "ERR_AUTHZ_ROLE_INVALID", path: ["value"] })],
        },
      }),
    });
  });

  it("a user cannot remove their own role: the new role must have promote_users", async () => {
    const adele = await as("adele");
    const refused = await adele.put("/users/adele/role", { role: "subscriber" });
    expect(refused).toEqual({
      status: 403,
      body: expect.objectContaining({ message: "Sorry, you cannot remove your own role." }),
    });
    expect((await adele.put("/posts/7", { title: "Still an administrator" })).status).toBe(200);
  });

  it("without filtering editable_roles, anyone allowed to change roles makes others administrators, even an editor: she need not hold what the role gives", async () => {
    const changed = await (await as("elena")).put("/users/cora/role", { role: "administrator" });
    expect(changed).toEqual({ status: 200, body: { user: "cora", role: "administrator" } });
    expect(
      (await (await as("cora")).put("/posts/7", { title: "Otto's notes, by Cora" })).status,
    ).toBe(200);
  });
});

describe("WordPress: roles kept in the site's data", () => {
  it("a capability added to a role (WP_Roles::add_cap) reaches every user who holds the role, on their next request", async () => {
    const arthur = await as("arthur");
    expect((await arthur.get("/posts/7")).status).toBe(403);
    addCap(wordpress.db, "author", cap.read_private_posts);
    expect((await arthur.get("/posts/7")).status).toBe(200);
    expect((await (await as("otto")).get("/posts/3")).status).toBe(200);
  });

  it("wp role reset puts a default role back to its default capabilities", async () => {
    resetRole(wordpress.db, "author");
    expect((await (await as("arthur")).get("/posts/7")).status).toBe(403);
  });

  it("a role added at run time (add_role) is given with Change role to…, and its holder gets its capabilities", async () => {
    expect((await (await as("nora")).get("/posts/7")).status).toBe(403);
    addRole(wordpress.db, "reviewer", [cap.read, cap.read_private_posts]);
    const changed = await (await as("adele")).put("/users/nora/role", { role: "reviewer" });
    expect(changed).toEqual({ status: 200, body: { user: "nora", role: "reviewer" } });
    expect((await (await as("nora")).get("/posts/7")).status).toBe(200);
  });
});
