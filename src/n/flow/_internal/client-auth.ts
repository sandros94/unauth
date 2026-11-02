import { base64Stringify } from "unsecure/utils";
import { sign } from "unjwt/jws";
import { configError } from "./http/shared.ts";
import { createJti } from "../random.ts";
import type { OAuthProvider } from "../types.ts";

/** How long a `private_key_jwt` client assertion stays valid. */
const ASSERTION_LIFETIME = 60;

/** Adds the client authentication `provider.tokenAuth` names to a token request (RFC 6749 §2.3, RFC 7523 §2.2). */
export async function authenticateClient(
  provider: OAuthProvider<unknown>,
  request: { body: URLSearchParams; headers: Headers; endpoint: string; now: () => number },
): Promise<void> {
  const { client } = provider;
  const { body, headers } = request;
  const clientIdParameter = provider.clientIdParameter ?? "client_id";
  switch (provider.tokenAuth) {
    case "basic": {
      // RFC 6749 §2.3.1: each half is form-encoded before the pair is base64-encoded.
      const pair = `${formEncode(client.id)}:${formEncode(await secretOf(client))}`;
      headers.set("authorization", `Basic ${base64Stringify(pair)}`);
      return;
    }
    case "body": {
      body.set(clientIdParameter, client.id);
      body.set("client_secret", await secretOf(client));
      return;
    }
    case "private_key_jwt": {
      if (!client.privateKey) {
        throw configError(
          `OAuthProvider ${JSON.stringify(provider.id)} needs "client.privateKey".`,
        );
      }
      const assertion = await sign(
        { iss: client.id, sub: client.id, aud: request.endpoint, jti: createJti() },
        client.privateKey,
        {
          currentDate: new Date(request.now()),
          issuedAt: true,
          expiresIn: ASSERTION_LIFETIME,
        },
      );
      body.set(clientIdParameter, client.id);
      body.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
      body.set("client_assertion", assertion);
      return;
    }
    case "none": {
      body.set(clientIdParameter, client.id);
    }
  }
}

/** The client secret, from its value or its function; `ERR_UNAUTH_CONFIG_INVALID` for an empty one. */
async function secretOf(client: OAuthProvider<unknown>["client"]): Promise<string> {
  const { secret } = client;
  const value = typeof secret === "function" ? await secret() : secret;
  if (typeof value !== "string" || value === "") {
    throw configError(
      `The client ${JSON.stringify(client.id)} authenticates with a secret and "client.secret" gave none.`,
    );
  }
  return value;
}

function formEncode(value: string): string {
  return new URLSearchParams({ v: value }).toString().slice(2);
}
