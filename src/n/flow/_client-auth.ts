import { sign } from "unjwt";
import { base64Stringify } from "unsecure";
import { configError } from "./_http.ts";
import type { Provider } from "./types.ts";

/** How long a `private_key_jwt` client assertion stays valid. */
const ASSERTION_LIFETIME = 60;

/** Adds the client authentication `provider.tokenAuth` names to a token request (RFC 6749 §2.3, RFC 7523 §2.2). */
export async function authenticateClient(
  provider: Provider<unknown>,
  request: { body: URLSearchParams; headers: Headers; endpoint: string; now: () => number },
): Promise<void> {
  const { client } = provider;
  const { body, headers } = request;
  switch (provider.tokenAuth) {
    case "basic": {
      // RFC 6749 §2.3.1: each half is form-encoded before the pair is base64-encoded.
      const pair = `${formEncode(client.id)}:${formEncode(await secretOf(client))}`;
      headers.set("authorization", `Basic ${base64Stringify(pair)}`);
      return;
    }
    case "body": {
      body.set("client_id", client.id);
      body.set("client_secret", await secretOf(client));
      return;
    }
    case "private_key_jwt": {
      if (!client.privateKey) {
        throw configError(`Provider ${JSON.stringify(provider.id)} needs "client.privateKey".`);
      }
      const iat = Math.floor(request.now() / 1000);
      const assertion = await sign(
        {
          iss: client.id,
          sub: client.id,
          aud: request.endpoint,
          jti: crypto.randomUUID(),
          iat,
          exp: iat + ASSERTION_LIFETIME,
        },
        client.privateKey,
      );
      body.set("client_id", client.id);
      body.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
      body.set("client_assertion", assertion);
      return;
    }
    case "none": {
      body.set("client_id", client.id);
    }
  }
}

async function secretOf(client: Provider<unknown>["client"]): Promise<string> {
  const { secret } = client;
  return typeof secret === "function" ? secret() : (secret ?? "");
}

function formEncode(value: string): string {
  return new URLSearchParams({ v: value }).toString().slice(2);
}
