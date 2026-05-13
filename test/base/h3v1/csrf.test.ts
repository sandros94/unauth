import { describe, it, expect, beforeEach } from "vitest";
import { eventHandler } from "h3v1";

import { defineCsrf } from "../../../src/base/h3v1/csrf.ts";

import { parseCookie } from "../_internal/cookies.ts";
import { createH3v1Harness, type H3v1Harness } from "./_utils.ts";

describe("defineCsrf (h3v1)", () => {
  let h: H3v1Harness;
  const csrf = defineCsrf({
    secret: "test-secret",
    cookie: { secure: false },
  });

  beforeEach(() => {
    h = createH3v1Harness();
  });

  it("sets CSRF cookie on safe methods", async () => {
    h.router.get(
      "/",
      eventHandler({
        onRequest: csrf,
        handler: () => ({ ok: true }),
      }),
    );

    const res = await h.request("/");
    const token = parseCookie(res.headers, "csrf");
    expect(token).toBeTypeOf("string");
    expect(token!.length).toBeGreaterThan(0);
  });

  it("does not overwrite existing CSRF cookie", async () => {
    h.router.get(
      "/",
      eventHandler({
        onRequest: csrf,
        handler: () => ({ ok: true }),
      }),
    );

    const res1 = await h.request("/");
    const token1 = parseCookie(res1.headers, "csrf");

    const res2 = await h.request("/", {
      headers: {
        Cookie: `csrf=${token1}`,
      },
    });
    const token2 = parseCookie(res2.headers, "csrf");

    // No new Set-Cookie when cookie already present
    expect(token2).toBeUndefined();
  });

  it("rejects POST without CSRF tokens", async () => {
    h.router.post(
      "/",
      eventHandler({
        onRequest: csrf,
        handler: () => ({ ok: true }),
      }),
    );

    const res = await h.request("/", { method: "POST" });
    expect(res.status).toBe(403);
  });

  it("rejects POST with mismatched tokens", async () => {
    h.router.post(
      "/",
      eventHandler({
        onRequest: csrf,
        handler: () => ({ ok: true }),
      }),
    );

    const res = await h.request("/", {
      method: "POST",
      headers: {
        Cookie: "csrf=real-token",
      },
    });
    expect(res.status).toBe(403);
  });

  it("accepts POST with matching tokens", async () => {
    h.router.get(
      "/",
      eventHandler({
        onRequest: csrf,
        handler: () => ({ ok: true }),
      }),
    );
    h.router.post(
      "/",
      eventHandler({
        onRequest: csrf,
        handler: () => ({ ok: true }),
      }),
    );

    // GET to obtain CSRF cookie
    const getRes = await h.request("/");
    const csrfToken = parseCookie(getRes.headers, "csrf")!;
    expect(csrfToken).toBeTypeOf("string");

    // POST with matching cookie + header
    const postRes = await h.request("/", {
      method: "POST",
      headers: {
        Cookie: `csrf=${csrfToken}`,
        "x-csrf-token": csrfToken,
      },
    });
    expect(postRes.status).toBe(200);
    const postBody = await postRes.json();
    expect(postBody.ok).toBe(true);
  });

  it("uses custom cookie and header names", async () => {
    const custom = defineCsrf({
      secret: "test-secret",
      name: "my-csrf",
      headerName: "x-my-csrf",
      cookie: { secure: false },
    });

    h.router.get(
      "/",
      eventHandler({
        onRequest: custom,
        handler: () => ({ ok: true }),
      }),
    );
    h.router.post(
      "/",
      eventHandler({
        onRequest: custom,
        handler: () => ({ ok: true }),
      }),
    );

    const getRes = await h.request("/");
    const token = parseCookie(getRes.headers, "my-csrf")!;
    expect(token).toBeTypeOf("string");

    // Using the custom header name
    const postRes = await h.request("/", {
      method: "POST",
      headers: {
        Cookie: `my-csrf=${token}`,
        "x-my-csrf": token,
      },
    });
    expect(postRes.status).toBe(200);
    const postBody = await postRes.json();
    expect(postBody.ok).toBe(true);

    // Wrong header name fails
    const failRes = await h.request("/", {
      method: "POST",
      headers: {
        Cookie: `my-csrf=${token}`,
        "x-csrf-token": token,
      },
    });
    expect(failRes.status).toBe(403);
  });
});
