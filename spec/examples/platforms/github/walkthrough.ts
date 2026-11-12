import { defineAuthz } from "unauth/z";
import { afterAll, afterEach, assert, beforeAll, describe, expect, it, vi } from "vitest";
import { sqlAgreed, sqlReached } from "../check.ts";
import { type Caller, signedIn, visitor } from "../client.ts";
import { type GitHub, createGitHub } from "./app.ts";
import { authz } from "./authz.ts";
import { seed } from "./seed.ts";

const deployed = vi.hoisted((): { authz?: typeof authz } => ({}));

vi.mock(import("../../storage/ask.ts"), async (original) =>
  (await import("../check.ts")).againstAsk(await original()),
);

vi.mock(import("./authz.ts"), async (original) => {
  const module = await original();
  return {
    ...module,
    get authz() {
      return deployed.authz ?? module.authz;
    },
  };
});

let github: GitHub;
const as = (user: string): Promise<Caller> => signedIn(github.app, user);
const push = (caller: Caller, repo: string, branch: string) =>
  caller.post(`/repos/acme/${repo}/pushes`, { branch });
const grantsHeldBy = (user: string): unknown => {
  const row = github.db
    .prepare("SELECT data FROM sessions WHERE subject = ? ORDER BY rowid DESC LIMIT 1")
    .get(user);
  return JSON.parse(String(row?.data)).grants;
};

beforeAll(() => {
  github = createGitHub();
  seed(github.db);
});

afterEach(sqlAgreed);
afterAll(sqlReached);

describe("GitHub: who reads a repository", () => {
  it("public repositories are accessible to everyone on the internet", async () => {
    const reply = await visitor(github.app).get("/repos/acme/docs");
    expect(reply).toEqual({
      status: 200,
      body: { org: "acme", name: "docs", visibility: "public" },
    });
  });

  it("private repositories are only accessible to the people given access", async () => {
    expect((await visitor(github.app).get("/repos/acme/api")).status).toBe(401);
    expect((await (await as("vera")).get("/repos/acme/api")).status).toBe(403);
  });

  it("base permissions apply to all members, on any of the organization's repositories", async () => {
    const nina = await as("nina");
    expect((await nina.get("/repos/acme/api")).status).toBe(200);
    expect((await nina.get("/repos/acme/web")).status).toBe(200);
    expect((await push(nina, "api", "fix")).status).toBe(403);
  });

  it("an outside collaborator reaches the repositories given and no other: base permissions do not apply", async () => {
    const carl = await as("carl");
    expect((await carl.get("/repos/acme/api")).status).toBe(200);
    expect((await carl.get("/repos/acme/web")).status).toBe(403);
  });

  it("internal repositories are not visible outside the enterprise, outside collaborators included", async () => {
    expect((await (await as("carl")).get("/repos/acme/handbook")).status).toBe(403);
  });

  it("enterprise members read every internal repository, in organizations they are not a member of too", async () => {
    const lena = await as("lena");
    expect((await lena.get("/repos/acme/handbook")).status).toBe(200);
    expect((await lena.get("/repos/acme/web")).status).toBe(403);
  });

  it("internal repositories are readable even where the base permission is none", async () => {
    const lena = await as("lena");
    expect((await lena.get("/repos/acme-labs/notes")).status).toBe(200);
    expect((await lena.get("/repos/acme-labs/lab")).status).toBe(403);
  });

  it("an enterprise owner outside every organization does not reach its repositories", async () => {
    const erin = await as("erin");
    expect((await erin.get("/repos/acme/api")).status).toBe(403);
    expect((await erin.get("/repos/acme/handbook")).status).toBe(403);
  });
});

describe("GitHub: repository roles and teams", () => {
  it("organization owners have admin access to every repository of the organization", async () => {
    const olivia = await as("olivia");
    expect((await olivia.get("/repos/acme/web")).status).toBe(200);
    expect((await olivia.post("/repos/acme/web/issues/1/labels", { label: "bug" })).status).toBe(
      201,
    );
  });

  it("applying labels takes triage or above: read does not, write does", async () => {
    const label = { label: "bug" };
    expect((await (await as("carl")).post("/repos/acme/api/issues/1/labels", label)).status).toBe(
      403,
    );
    expect((await (await as("tess")).post("/repos/acme/api/issues/1/labels", label)).status).toBe(
      201,
    );
  });

  it("child teams inherit the parent's access permissions", async () => {
    const tess = await as("tess");
    expect(await push(tess, "api", "feature")).toEqual({
      status: 201,
      body: { branch: "feature" },
    });
    expect((await push(tess, "web", "feature")).status).toBe(201);
  });

  it("changing a repository's visibility takes admin: maintain is refused", async () => {
    const reply = await (
      await as("tess")
    ).put("/repos/acme/web/visibility", { visibility: "public" });
    expect(reply.status).toBe(403);
  });

  it("changing from private to internal gives every member of the enterprise read access", async () => {
    const olivia = await as("olivia");
    expect(
      (await olivia.put("/repos/acme/web/visibility", { visibility: "internal" })).status,
    ).toBe(200);
    expect((await (await as("lena")).get("/repos/acme/web")).status).toBe(200);
    expect((await (await as("carl")).get("/repos/acme/web")).status).toBe(403);
  });

  it("a team is granted a role on a repository, and its members hold it", async () => {
    const olivia = await as("olivia");
    expect((await olivia.put("/repos/acme/web/teams/release", { role: "write" })).status).toBe(200);
    expect((await push(await as("rob"), "web", "feature")).status).toBe(201);
  });
});

describe("GitHub: members and outside collaborators", () => {
  it("anyone with admin access to a repository adds outside collaborators, and nobody below admin does", async () => {
    const ada = await as("ada");
    const added = await ada.put("/repos/acme/api/collaborators/vera", { role: "triage" });
    expect(added).toEqual({ status: 200, body: { user: "vera", role: "triage", outside: true } });
    expect((await (await as("vera")).get("/repos/acme/api")).status).toBe(200);
    const refused = await (
      await as("tess")
    ).put("/repos/acme/api/collaborators/carl", { role: "write" });
    expect(refused.status).toBe(403);
  });

  it("the organization can restrict adding outside collaborators to its owners", async () => {
    const ada = await as("ada");
    const olivia = await as("olivia");
    expect((await ada.put("/orgs/acme/outside-collaborators", { policy: "owners" })).status).toBe(
      403,
    );
    expect(
      (await olivia.put("/orgs/acme/outside-collaborators", { policy: "owners" })).status,
    ).toBe(200);
    expect((await ada.put("/repos/acme/api/collaborators/lena", { role: "read" })).status).toBe(
      403,
    );
    expect((await olivia.put("/repos/acme/api/collaborators/lena", { role: "read" })).status).toBe(
      200,
    );
  });

  it("a member removed as a collaborator keeps access through the base permission", async () => {
    const ada = await as("ada");
    expect((await ada.put("/repos/acme/api/collaborators/rob", { role: "maintain" })).status).toBe(
      200,
    );
    expect((await push(await as("rob"), "api", "hotfix")).status).toBe(201);
    expect((await ada.delete("/repos/acme/api/collaborators/rob")).status).toBe(200);
    const rob = await as("rob");
    expect((await rob.get("/repos/acme/api")).status).toBe(200);
    expect((await push(rob, "api", "hotfix")).status).toBe(403);
  });

  it("teams are made of members only: an outside collaborator cannot join one", async () => {
    const olivia = await as("olivia");
    expect((await olivia.put("/orgs/acme/teams/release/members/carl")).status).toBe(422);
    expect((await olivia.put("/orgs/acme/teams/release/members/nina")).status).toBe(200);
    expect((await (await as("ada")).put("/orgs/acme/teams/release/members/tess")).status).toBe(403);
  });

  it("a base permission change is the owners', reaches every member, and never goes below read on internal repositories", async () => {
    const refused = await (
      await as("ada")
    ).put("/orgs/acme/base-permission", { permission: "none" });
    expect(refused.status).toBe(403);
    const olivia = await as("olivia");
    expect((await olivia.put("/orgs/acme/base-permission", { permission: "none" })).status).toBe(
      200,
    );
    const nina = await as("nina");
    expect((await nina.get("/repos/acme/api")).status).toBe(403);
    expect((await nina.get("/repos/acme/handbook")).status).toBe(200);
    expect((await olivia.put("/orgs/acme/base-permission", { permission: "write" })).status).toBe(
      200,
    );
    expect((await push(await as("nina"), "api", "docs")).status).toBe(201);
  });
});

describe("GitHub: protections and rulesets", () => {
  it("branch protection does not restrict admins nor custom roles allowed to bypass it", async () => {
    expect((await push(await as("tess"), "api", "main")).status).toBe(403);
    expect((await push(await as("ada"), "api", "main")).status).toBe(201);
    expect((await push(await as("mark"), "api", "main")).status).toBe(201);
  });

  it("'do not allow bypassing' applies the protection to admins and bypassing roles too", async () => {
    const ada = await as("ada");
    expect(
      (await ada.put("/repos/acme/api/branches/main/protection", { enforceAdmins: true })).status,
    ).toBe(200);
    expect((await push(ada, "api", "main")).status).toBe(403);
    expect((await push(await as("mark"), "api", "main")).status).toBe(403);
  });

  it("a ruleset restricts even owners and admins who are not on its bypass list", async () => {
    const reply = await push(await as("olivia"), "web", "main");
    expect(reply.status).toBe(403);
    expect(reply.body).toEqual(
      expect.objectContaining({ message: "Ruleset main-guard blocks the push." }),
    );
    expect((await push(await as("tess"), "web", "main")).status).toBe(403);
  });

  it("managing rulesets is admin only, and an admin puts a team on the bypass list without bypassing it", async () => {
    const path = "/repos/acme/web/rulesets/main-guard/bypass-teams/release";
    const refused = await (await as("tess")).put(path);
    expect(refused.status).toBe(403);
    expect((await (await as("olivia")).put(path)).status).toBe(200);
    expect((await push(await as("rob"), "web", "main")).status).toBe(201);
    expect((await push(await as("olivia"), "web", "main")).status).toBe(403);
  });

  it("a role on the bypass list lets its holders bypass: admin, then maintain", async () => {
    const olivia = await as("olivia");
    const path = "/repos/acme/web/rulesets/main-guard/bypass-role";
    expect((await olivia.put(path, { role: "admin" })).status).toBe(200);
    expect((await push(olivia, "web", "main")).status).toBe(201);
    expect((await push(await as("tess"), "web", "main")).status).toBe(403);
    expect((await olivia.put(path, { role: "maintain" })).status).toBe(200);
    expect((await push(await as("tess"), "web", "main")).status).toBe(201);
  });
});

describe("GitHub: a deploy that changes a preset", () => {
  it("a session open before the deploy is answered with the new preset on its next request: its grants are issued again", async () => {
    const carl = await as("carl");
    const label = { label: "bug" };
    expect((await carl.post("/repos/acme/api/issues/1/labels", label)).status).toBe(403);
    const { data } = authz.catalog;
    assert(data.presets);
    deployed.authz = defineAuthz({ ...data, presets: { ...data.presets, read: ["repo:triage"] } });
    expect(authz.diverged(grantsHeldBy("carl"))).toEqual({
      segments: ["presets"],
      permissions: [],
      presets: ["read"],
    });
    expect((await carl.post("/repos/acme/api/issues/1/labels", label)).status).toBe(201);
    expect(authz.diverged(grantsHeldBy("carl"))).toBeUndefined();
  });
});
