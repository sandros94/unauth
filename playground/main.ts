import { H3, HTTPError, serve, readBody } from "h3";
import { OIDCProvider, generateJwk } from "unauth";

// In a real app, load keys from secure storage and rotate periodically.
const [accessKey, idKey] = await Promise.all([
  generateJwk("Ed25519", { params: { kid: "at-1" } }),
  generateJwk("Ed25519", { params: { kid: "id-1" } }),
]);
const refreshKey = "a-strong-secret"; // can also be a JWK

// Keep issuer consistent with where this server runs.
const issuer = "http://localhost:3000";

const app = new H3();
const oidc = new OIDCProvider({
  issuer,
  accessToken: { privateKey: accessKey.privateKey },
  refreshToken: { privateKey: refreshKey },
  idToken: { privateKey: idKey.privateKey },
  defaultScope: "openid profile email",
  availableScopes: ["openid", "profile", "email"],
  jwks: [accessKey.publicKey, idKey.publicKey],
});

// OpenID Provider Configuration (Discovery)
app.get("/.well-known/openid-configuration", () => {
  return oidc.getDiscoveryDocument({
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
  });
});

// JWKS (public keys)
app.get("/.well-known/jwks.json", () => oidc.getPublicJwks());

// Authorization endpoint (GET)
// Validates OIDC request (requires scope=openid and PKCE), issues code, and redirects back to client.
app.get("/authorize", async (event) => {
  const q = event.url.searchParams;
  const resourceMulti = q.getAll("resource");
  const resource =
    resourceMulti.length > 1 ? resourceMulti : resourceMulti[0] || undefined;
  const rt = q.get("response_type") || "code";
  if (rt !== "code") {
    throw HTTPError.status(400, `Unsupported response_type: ${rt}`);
  }
  const req = {
    response_type: "code" as const,
    client_id: q.get("client_id") || "",
    redirect_uri: q.get("redirect_uri") || "",
    scope: q.get("scope") || undefined,
    state: q.get("state") || undefined,
    code_challenge: q.get("code_challenge") || undefined,
    code_challenge_method:
      (q.get("code_challenge_method") as "plain" | "S256" | null) || undefined,
    // OIDC extras (not strictly required for code flow)
    nonce: q.get("nonce") || undefined,
    resource,
  } as const;

  try {
    const result = await oidc.authorize(req, async () => ({
      // In real app, ensure the user is authenticated and provide their subject
      sub: "user-123",
    }));
    const redirect = oidc.buildAuthorizeRedirect(req.redirect_uri, result, {
      iss: oidc.issuer,
    });
    return new Response(null, {
      status: 302,
      headers: { Location: redirect.toString() },
    });
  } catch (error_: any) {
    // If we have a redirect_uri, return OAuth error via redirect
    if (req.redirect_uri) {
      const error = oidc.authorizeError(
        "invalid_request",
        error_?.message,
        req.state || undefined,
      );
      const redirect = oidc.buildAuthorizeRedirect(req.redirect_uri, error, {
        iss: oidc.issuer,
      });
      return new Response(null, {
        status: 302,
        headers: { Location: redirect.toString() },
      });
    }
    throw new HTTPError("Invalid authorization request", {
      status: 400,
      cause: error_,
    });
  }
});

// Token endpoint (POST)
// Supports authorization_code, refresh_token, and client_credentials
app.post("/token", async (event) => {
  const b = await readBody<{
    grant_type?: string;
    code?: string;
    redirect_uri?: string;
    client_id?: string;
    code_verifier?: string;
    refresh_token?: string;
    scope?: string;
    resource?: string | string[];
    aud?: string | string[];
  }>(event).catch(() => undefined);

  if (!b) throw HTTPError.status(400, "Invalid or missing request body");

  const grantType = b.grant_type as string | undefined;
  if (!grantType) throw HTTPError.status(400, "Missing grant_type");

  try {
    if (grantType === "authorization_code") {
      const tokens = await oidc.tokenAuthorizationCode(
        {
          grant_type: "authorization_code",
          code: String(b.code || ""),
          client_id: String(b.client_id || ""),
          code_verifier: b.code_verifier ? String(b.code_verifier) : undefined,
          redirect_uri: b.redirect_uri ? String(b.redirect_uri) : undefined,
          resource: b.resource,
        },
        async (claims) => ({
          accessTokenClaims: {
            // Prefer request resource or code-captured resource
            aud: b.resource ?? claims.resource ?? "api://default",
          },
          refreshTokenClaims: {},
        }),
      );

      // Optional OIDC: return ID Token when scope includes openid
      let id_token: string | undefined;
      const at = await oidc.introspectAccessToken(tokens.access_token);
      if (at.active && at.claims?.sub) {
        const sub = at.claims.sub;
        id_token = await oidc.buildIdToken({
          subject: sub,
          audience: String(b.client_id || ""),
          // Nonce is not available at the token endpoint in pure code flow here
          access_token: tokens.access_token,
        });
      }
      return { ...tokens, ...(id_token ? { id_token } : {}) };
    }

    if (grantType === "refresh_token") {
      const tokens = await oidc.tokenRefreshToken(
        {
          grant_type: "refresh_token",
          refresh_token: String(b.refresh_token || ""),
          client_id: String(b.client_id || ""),
          scope: b.scope ? String(b.scope) : undefined,
          resource: b.resource,
        },
        async (claims) => ({
          accessTokenClaims: {
            aud: b.resource ?? claims.resource ?? "api://default",
          },
          refreshTokenClaims: {},
        }),
      );
      return tokens;
    }

    if (grantType === "client_credentials") {
      const tokens = await oidc.tokenClientCredentials(
        {
          grant_type: "client_credentials",
          scope: b.scope ? String(b.scope) : undefined,
          aud: b.aud,
          resource: b.resource,
          client_id: b.client_id ? String(b.client_id) : undefined,
        },
        async (opts) => ({
          // Authenticate your client here (e.g., client_id/secret, mTLS, etc.)
          sub: String(b.client_id || "service-client"),
          scope: String(b.scope || opts.defaultScope || "openid"),
          aud: b.aud ?? b.resource ?? "api://default",
        }),
      );
      return tokens;
    }

    throw HTTPError.status(400, `Unsupported grant_type: ${grantType}`);
  } catch (error_) {
    throw new HTTPError("Invalid token request", {
      status: 400,
      cause: error_,
    });
  }
});

// UserInfo endpoint (GET)
// Requires a valid Bearer access token. Returns a minimal OIDC UserInfo response.
app.get("/userinfo", async (event) => {
  const auth = event.req.headers.get("Authorization");
  if (!auth || !auth.toLowerCase().startsWith("bearer ")) {
    throw HTTPError.status(401, "Missing or invalid Authorization header");
  }
  const token = auth.slice("bearer ".length);
  const res = await oidc.introspectAccessToken(token);
  if (!res.active || !res.claims?.sub) {
    throw HTTPError.status(401, "Invalid or expired access token");
  }

  // Build a minimal profile. Extend as needed with additional claims from your datastore.
  return oidc.buildUserInfo({ sub: res.claims.sub });
});

serve(app);
