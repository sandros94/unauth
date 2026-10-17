import { describe, expect, it, vi } from "vitest";

import {
  type IdentityStore,
  type ProvenIdentity,
  isUnauthError,
  signIn,
} from "../../src/n/index.ts";

interface User {
  id: string;
  name: string;
}

function identity(subject: string, extra: Partial<ProvenIdentity> = {}): ProvenIdentity {
  return {
    provider: "github",
    subject,
    profile: {},
    email: "ada@example.com",
    emailVerified: true,
    tokens: { access_token: "at-1", token_type: "Bearer", raw: {} },
    ...extra,
  };
}

/** An in-memory store keyed by `provider:subject`. */
function memoryStore(users: Record<string, User> = {}) {
  const owners = new Map<string, string>(Object.entries({}));
  const byId = new Map<string, User>(Object.entries(users));
  const store: IdentityStore<User> = {
    findByIdentity: vi.fn(async ({ provider, subject }) => {
      const owner = owners.get(`${provider}:${subject}`);
      return owner === undefined ? undefined : byId.get(owner);
    }),
    create: vi.fn(async (proven) => {
      const user = { id: `u-${byId.size + 1}`, name: proven.subject };
      byId.set(user.id, user);
      owners.set(`${proven.provider}:${proven.subject}`, user.id);
      return user;
    }),
    link: vi.fn(async (userId, proven) => {
      owners.set(`${proven.provider}:${proven.subject}`, userId);
      return byId.get(userId)!;
    }),
  };
  return { store, owners, byId };
}

describe("signIn", () => {
  it("creates a user for an unknown identity", async () => {
    const { store } = memoryStore();

    const result = await signIn(identity("gh-1"), { identities: store });

    expect(result).toEqual({ user: { id: "u-1", name: "gh-1" }, created: true, linked: false });
    expect(store.create).toHaveBeenCalledWith(identity("gh-1"));
  });

  it("returns the owner of a known identity", async () => {
    const { store } = memoryStore();
    await signIn(identity("gh-1"), { identities: store });

    const result = await signIn(identity("gh-1"), { identities: store });

    expect(result).toEqual({ user: { id: "u-1", name: "gh-1" }, created: false, linked: false });
    expect(store.create).toHaveBeenCalledOnce();
  });

  it("links an unclaimed identity to the user asking for it", async () => {
    const { store } = memoryStore({ "u-9": { id: "u-9", name: "Ada" } });

    const result = await signIn(identity("gh-2"), {
      identities: store,
      link: { userId: "u-9" },
      currentUserId: "u-9",
    });

    expect(result).toEqual({ user: { id: "u-9", name: "Ada" }, created: false, linked: true });
    expect(store.link).toHaveBeenCalledWith("u-9", identity("gh-2"));
    expect(store.create).not.toHaveBeenCalled();
  });

  it("treats linking an identity the user already owns as a sign-in", async () => {
    const { store, owners } = memoryStore({ "u-9": { id: "u-9", name: "Ada" } });
    owners.set("github:gh-2", "u-9");

    const result = await signIn(identity("gh-2"), {
      identities: store,
      link: { userId: "u-9" },
      currentUserId: "u-9",
    });

    expect(result).toEqual({ user: { id: "u-9", name: "Ada" }, created: false, linked: false });
    expect(store.link).not.toHaveBeenCalled();
  });

  it("throws ERR_AUTHN_LINK_CONFLICT (409) for an identity owned by another user", async () => {
    const { store, owners } = memoryStore({
      "u-1": { id: "u-1", name: "Owner" },
      "u-9": { id: "u-9", name: "Ada" },
    });
    owners.set("github:gh-2", "u-1");

    const error = await signIn(identity("gh-2"), {
      identities: store,
      link: { userId: "u-9" },
      currentUserId: "u-9",
    }).catch((error_: unknown) => error_);

    expect(isUnauthError(error, "ERR_AUTHN_LINK_CONFLICT")).toBe(true);
    expect(isUnauthError(error) && error.status).toBe(409);
    expect(store.link).not.toHaveBeenCalled();
  });

  it.each([
    ["another signed-in user", "u-1"],
    ["no signed-in user", undefined],
  ])(
    "throws ERR_AUTHN_LINK_CHANGED (409) when the link was asked by %s, before touching the store",
    async (_label, currentUserId) => {
      const { store } = memoryStore({ "u-9": { id: "u-9", name: "Ada" } });

      const error = await signIn(identity("gh-2"), {
        identities: store,
        link: { userId: "u-9" },
        currentUserId,
      }).catch((error_: unknown) => error_);

      expect(isUnauthError(error, "ERR_AUTHN_LINK_CHANGED")).toBe(true);
      expect(isUnauthError(error) && error.status).toBe(409);
      expect(isUnauthError(error) && error.cause).toEqual({ linkUserId: "u-9" });
      expect(store.findByIdentity).not.toHaveBeenCalled();
      expect(store.link).not.toHaveBeenCalled();
      expect(store.create).not.toHaveBeenCalled();
    },
  );

  it("never links by email: a known email on a new identity creates a new user", async () => {
    const { store } = memoryStore();
    await signIn(identity("gh-1"), { identities: store });

    const result = await signIn(identity("google-1", { provider: "google" }), {
      identities: store,
    });

    expect(result.created).toBe(true);
    expect(result.user.id).toBe("u-2");
  });
});
