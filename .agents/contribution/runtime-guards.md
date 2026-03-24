# Runtime Guards for Security-Critical Options

TypeScript types enforce required fields at compile time, but JavaScript consumers
don't benefit from this. For any option that is **security-critical**, add an
eager runtime check at factory call time (not at first request).

## Pattern

```ts
export function defineTokenPair(options) {
  if (!options.access.maxAge) {
    throw new Error("[unauth] access.maxAge is required for defineTokenPair");
  }
  // ... rest of factory
}
```

## When to apply

Add runtime guards for options where a missing value would:

- Silently produce tokens/sessions that never expire
- Disable a security feature without the developer's awareness
- Default to an insecure configuration

## Conventions

- Throw a plain `Error` (not `HTTPError` — this is a developer mistake, not an HTTP error)
- Prefix with `[unauth]` for easy identification in logs
- Include the option path and function name: `[unauth] access.maxAge is required for defineTokenPair`
- Check eagerly in the factory function, not in the returned composable/middleware
- Always pair with a TypeScript type that makes the field required (belt and suspenders)

## Where this applies today

- `defineTokenPair` — `access.maxAge` and `refresh.maxAge`

## Where this will apply in future

- OAuth 2.1 provider: authorization code lifetime, token lifetimes
- OIDC: ID token maxAge, session absolute expiry
- Any new primitive where a missing duration is a security risk
