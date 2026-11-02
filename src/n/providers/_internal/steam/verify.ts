import { postText } from "../../../flow/_internal/http/form.ts";
import { type Fetch, providerError } from "../../../flow/_internal/http/shared.ts";

/**
 * Direct verification (OpenID 2.0 §11.4.2): every `openid.*` field of the assertion, `openid.mode`
 * replaced by `check_authentication`, POSTed to the OP endpoint; the answer is its Key-Value Form
 * body (§4.1.1) with `is_valid` present. An unreachable, slow, oversized, failed or malformed
 * answer is `ERR_AUTHN_PROVIDER_ERROR`, its `cause.reason` saying which.
 */
export async function checkAuthentication(
  params: Record<string, string>,
  options: { endpoint: string; fetch: Fetch; label: string; timeout?: number },
): Promise<Record<string, string>> {
  const { endpoint, label } = options;
  const form = new URLSearchParams();
  for (const [name, value] of Object.entries(params)) {
    if (!name.startsWith("openid.")) continue;
    form.append(name, name === "openid.mode" ? "check_authentication" : value);
  }
  const answer = await postText(endpoint, form, {
    fetch: options.fetch,
    label,
    timeout: options.timeout,
  });
  if (!answer.ok) {
    throw providerError(`The ${label} answered ${answer.status} to check_authentication.`, {
      reason: "status",
      status: answer.status,
    });
  }
  const fields = keyValueForm(answer.text);
  if (fields === undefined || fields.is_valid === undefined) {
    throw providerError(`The ${label} did not answer check_authentication in Key-Value Form.`, {
      reason: "malformed",
      status: answer.status,
    });
  }
  return fields;
}

/** A Key-Value Form body (OpenID 2.0 §4.1.1): one `key:value` per line; `undefined` when a line is not one. */
function keyValueForm(text: string): Record<string, string> | undefined {
  const object: Record<string, string> = Object.create(null);
  for (const line of text.split("\n")) {
    if (line === "") continue;
    const colon = line.indexOf(":");
    if (colon === -1) return undefined;
    const name = line.slice(0, colon);
    if (name !== "__proto__") object[name] = line.slice(colon + 1);
  }
  return object;
}
