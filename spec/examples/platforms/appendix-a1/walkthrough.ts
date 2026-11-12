import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { sqlAgreed, sqlReached } from "../check.ts";
import { type Caller, signedIn } from "../client.ts";
import { type AppendixA1, createAppendixA1 } from "./app.ts";
import { seed } from "./seed.ts";

vi.mock(import("../../storage/ask.ts"), async (original) =>
  (await import("../check.ts")).againstAsk(await original()),
);

let a1: AppendixA1;
const as = (user: string): Promise<Caller> => signedIn(a1.app, user);
const allow = (subject: string, permission: string) => ({ subject, permission });

beforeAll(() => {
  a1 = createAppendixA1();
  seed(a1.db);
});

afterEach(sqlAgreed);
afterAll(sqlReached);

describe("A.1: one person and an assistant, no places", () => {
  it("the assistant reads a post: allowed; drafts one: allowed; publishes one: denied, nothing gives it", async () => {
    const assistant = await as("assistant");
    expect(await assistant.get("/posts/1")).toEqual({ status: 200, body: { id: "1" } });
    expect(await assistant.post("/posts", {})).toEqual({ status: 201, body: { status: "draft" } });
    expect((await assistant.post("/posts/1/publish", {})).status).toBe(403);
  });

  it("Ed publishes a post: allowed", async () => {
    const reply = await (await as("ed")).post("/posts/1/publish", {});
    expect(reply).toEqual({ status: 200, body: { id: "1", status: "publish" } });
  });

  it("whether the assistant could have written that statement itself is the application's rule: here writing an allow takes access:manage, which the assistant does not hold", async () => {
    const reply = await (await as("assistant")).post("/allows", allow("assistant", "post:publish"));
    expect(reply.status).toBe(403);
  });

  it("the assistant is then allowed post:publish: from then on it publishes", async () => {
    const reply = await (await as("ed")).post("/allows", allow("assistant", "post:publish"));
    expect(reply).toEqual({
      status: 200,
      body: { subject: "assistant", permission: "post:publish" },
    });
    expect((await (await as("assistant")).post("/posts/1/publish", {})).status).toBe(200);
  });
});
