import type { ExpiresIn, SessionDefinition } from "unjwt/session";
import { type AuthConfigInput, resolveAuthConfig } from "./_session-config.ts";
import { authSessionManager, requireAuthenticated, withoutReserved } from "./_session-manager.ts";
import type { AuthSessionDefinition, AuthSessionRecord } from "./session.ts";

/** Any unjwt session factory, as the composition calls it. */
type SessionFactory = (
  config: Record<string, unknown>,
) => SessionDefinition<AuthSessionRecord, ExpiresIn>;

/**
 * The auth session over `define`, unjwt's `defineJWESession`/`defineJWSSession` over the Web
 * driver or one of your own. The public signatures type `config` against that factory; here it is
 * read loosely.
 */
export function composeAuthSession<TData extends AuthSessionRecord, TContext>(
  config: AuthConfigInput,
  options: { define: object },
): AuthSessionDefinition<TData, TContext> {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the public signatures type `define` against its config
  const define = options.define as SessionFactory;
  const inner = define(resolveAuthConfig(config));
  const definition: AuthSessionDefinition<AuthSessionRecord, unknown> = {
    use: async (context) => authSessionManager(await inner.use(context)),
    require: async (context) => requireAuthenticated(authSessionManager(await inner.use(context))),
    token: (context) => inner.token(context),
    issue: (data, issueOptions) => inner.issue(data && withoutReserved(data), issueOptions),
    open: (token) => inner.open(token),
  };
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- TData and TContext come from the factory the caller typed
  return definition as unknown as AuthSessionDefinition<TData, TContext>;
}
