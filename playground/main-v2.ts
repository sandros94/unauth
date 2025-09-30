import { H3, serve, HTTPError, getQuery, readBody } from "h3v2";
import { generateJWK } from "unauth/utils";
import {
  type AuthorizeRequest,
  type TokenRequest,
  OIDCProvider,
} from "unauth/oidc";

const app = new H3();

const [atJwk, idJwk] = await Promise.all([
  generateJWK("RS256", { kid: "at-rsa-1" }),
  generateJWK("RS256", { kid: "id-rsa-1" }),
]);
const provider = new OIDCProvider({
  issuer: "http://localhost:3000",
  authorizationCodeOptions: {
    privateKey: "ac-secret",
  },
  refreshTokenOptions: {
    privateKey: "rt-secret",
  },
  accessTokenOptions: {
    privateKey: atJwk.privateKey,
    publicKey: atJwk.publicKey,
  },
  idTokenOptions: {
    privateKey: idJwk.privateKey,
    publicKey: idJwk.publicKey,
  },
});

// OpenID Provider Configuration (Discovery)
app.get("/.well-known/openid-configuration", () => {
  return provider.discovery();
});

// JWKS (public keys)
app.get("/.well-known/jwks.json", () => provider.jwkSet);

// Simple callback endpoint for manual testing; not used by the scripted test (which intercepts the Location header)
app.get("/callback", (event) => {
  const q = event.url.searchParams;
  const code = q.get("code");
  const state = q.get("state");
  return `Callback received. code=${code ?? "<none>"} state=${state ?? "<none>"}`;
});

// Authorization endpoint (GET)
app.get("/authorize", async (event) => {
  const req = getQuery<AuthorizeRequest>(event);

  const validation = provider.validateAuthorizeRequest(req);

  if (!validation.success) {
    throw new HTTPError({
      status: 400,
      statusText: "Invalid request",
      cause: new Error(
        `${validation.error.error}: ${validation.error.error_description}`,
      ),
    });
  }
  const normalized = validation.value;

  const redirect = await provider.issueAuthorizationCode({
    ...normalized,
    subject: "user-123",
    redirect_uri: "http://localhost:3000/callback",
  });

  if (!redirect.success) {
    throw new HTTPError({
      status: 400,
      statusText: "Invalid request",
      cause: new Error(
        `${redirect.error.error}: ${redirect.error.error_description}`,
      ),
    });
  }

  return new Response(null, {
    status: 302,
    headers: { Location: redirect.value },
  });
});

// Token endpoint (POST)
// Supports authorization_code, refresh_token, and client_credentials
app.post("/token", async (event) => {
  const req = await readBody<TokenRequest>(event).catch(() => undefined);

  if (!req) throw HTTPError.status(400, "Invalid or missing request body");

  const validation = provider.validateTokenRequest(req);

  if (!validation.success) {
    throw new HTTPError({
      status: 400,
      statusText: "Invalid request",
      cause: new Error(
        `${validation.error.error}: ${validation.error.error_description}`,
      ),
    });
  }
  const normalized = validation.value;

  const tokenGrant = await provider.issueTokenGrant(normalized);

  return tokenGrant.success
    ? tokenGrant.value
    : new Response(JSON.stringify(tokenGrant.error), {
        status: 400,
        statusText: "Invalid request",
        headers: { "Content-Type": "application/json" },
      });
});

// UserInfo endpoint (GET)
// Requires a valid Bearer access token. Returns a minimal OIDC UserInfo response.
app.get("/userinfo", async (event) => {
  const auth = event.req.headers.get("Authorization");
  if (!auth || !auth.toLowerCase().startsWith("bearer ")) {
    throw HTTPError.status(401, "Missing or invalid Authorization header");
  }
  const token = auth.slice("bearer ".length);
  const res = await provider.introspectAccessToken(token);
  if (!res || !res?.sub) {
    throw HTTPError.status(401, "Invalid or expired access token");
  }

  // Build a minimal profile. Extend as needed with additional claims from your datastore.
  return provider.buildUserInfo({ sub: res.sub });
});

serve(app);
