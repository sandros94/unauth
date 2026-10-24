import { type CompleteFlowOptions, completeFlowWithReturnHost } from "./_internal/complete.ts";
import type { FlowResult, Provider } from "./types.ts";

/**
 * Completes a sign-in from the provider's redirect: consumes the flow (the cookie is expired even
 * when this throws), checks `state` and `iss`, redeems the code, verifies the id_token of an
 * OpenID Connect provider and maps the account through `provider.profile`. Every failure is an
 * `UnauthError` whose message names the stage and whose `cause` holds the detail. A mix-up
 * between providers is caught by the provider `id` bound into the flow record and by the RFC 9207
 * `iss` parameter: with `issuerParameter` on, `iss` must equal `provider.issuer`; otherwise a
 * missing one is accepted but one naming another issuer is not (`ERR_AUTHN_STATE_MISMATCH`, cause
 * `reason: "issuer"`). `TMemo` names the memo the flow was started with; the record does not
 * carry its type.
 */
export async function completeFlow<TProfile, TMemo = unknown>(
  provider: Provider<TProfile>,
  request: Request,
  options: CompleteFlowOptions,
): Promise<FlowResult<TProfile, TMemo>> {
  const { result } = await completeFlowWithReturnHost<TProfile, TMemo>(provider, request, options);
  return result;
}
