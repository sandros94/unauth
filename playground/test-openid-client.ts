import * as client from "openid-client";

/**
 * This script exercises the playground OIDC server using openid-client.
 * Steps:
 * 1) Discover OP configuration
 * 2) Build authorization URL with PKCE (scope=openid)
 * 3) Simulate browser redirect back (capture 302 Location manually)
 * 4) Exchange code for tokens
 * 5) Call userinfo
 */
try {
  const issuer = new URL("http://localhost:3000/oidc/v1");
  const redirectUri = new URL("http://localhost:3000/callback");
  const clientId = "test-client";

  // 1) Discovery (allow HTTP for local dev using execute hook)
  const config = await client.discovery(
    issuer,
    clientId,
    undefined,
    undefined,
    {
      execute: [client.allowInsecureRequests],
    },
  );
  console.log("discovered", config.serverMetadata(), "\n\n");

  // 2) Build auth URL with PKCE
  const code_verifier = client.randomPKCECodeVerifier();
  const code_challenge = await client.calculatePKCECodeChallenge(code_verifier);
  const state = client.randomState();
  const scope = "openid profile";

  const authUrl = client.buildAuthorizationUrl(config, {
    redirect_uri: redirectUri.toString(),
    scope,
    code_challenge,
    code_challenge_method: "S256",
    state,
    resource: "https://api.example.com/",
  });
  console.log("authorize:", authUrl.toString(), "\n\n");

  // 3) Simulate user-agent requesting /authorize and capture the 302
  const res = await fetch(authUrl, { redirect: "manual" });
  if (res.status !== 302) {
    throw new Error(`Expected 302 from /authorize, got ${res.status}`);
  }
  const location = res.headers.get("location");
  if (!location) throw new Error("Missing Location header");
  const callbackUrl = new URL(location);
  if (
    callbackUrl.origin + callbackUrl.pathname !==
    redirectUri.origin + redirectUri.pathname
  ) {
    throw new Error(`Unexpected redirect target: ${callbackUrl}`);
  }
  console.log("callback url:", callbackUrl.toString(), "\n\n");

  // 4) Exchange the code for tokens
  const tokens = await client
    .authorizationCodeGrant(config, callbackUrl, {
      pkceCodeVerifier: code_verifier,
      expectedState: state,
    })
    .catch((error_) => {
      console.error("Error during token exchange:", error_.cause);
      throw error_;
    });
  console.log("tokens:", tokens, "\n\n");

  // 5) Call userinfo (skip subject verification since we did not fetch ID Token claims)
  const userinfo = await client.fetchUserInfo(
    config,
    tokens.access_token,
    client.skipSubjectCheck,
  );
  console.log("userinfo:", userinfo, "\n\n");
} catch (error_) {
  console.error(error_);
  process.exitCode = 1;
}
