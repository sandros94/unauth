import { describe, expect, it } from "vitest";

import { buildAuthorizationUrl, defineOAuth2Provider, exchangeCode } from "../../../src/n/index.ts";

const provider = defineOAuth2Provider({
  id: "keyed",
  clientId: "key-1",
  clientSecret: "secret-1",
  authorization: "https://idp.test/authorize",
  token: "https://idp.test/token",
  userinfo: "https://idp.test/me",
  clientIdParameter: "client_key",
  tokenAuth: "body",
  pkce: false,
});

describe("clientIdParameter", () => {
  it("names the client in the authorization request", () => {
    const url = buildAuthorizationUrl(provider, {
      redirectUri: "https://app.test/cb",
      state: "s",
      params: { client_key: "spoofed", client_id: "spoofed" },
    });
    expect(url.searchParams.get("client_key")).toBe("key-1");
    expect(url.searchParams.has("client_id")).toBe(false);
  });

  it("names the client in the token request body", async () => {
    let body = "";
    await exchangeCode(provider, {
      code: "c",
      redirectUri: "https://app.test/cb",
      fetch: async (_url, init) => {
        body = init?.body instanceof URLSearchParams ? init.body.toString() : "";
        return Response.json({ access_token: "at", token_type: "Bearer" });
      },
    });
    const form = new URLSearchParams(body);
    expect(form.get("client_key")).toBe("key-1");
    expect(form.get("client_secret")).toBe("secret-1");
    expect(form.has("client_id")).toBe(false);
  });
});
