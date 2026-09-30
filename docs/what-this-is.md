# What this is (and is not)

Novolis.Security is a **token mint** and a **tenant authorization framework**, plus password hashing, encryption, and related helpers. It is a **library** you compose inside your product host. It is **not** a full Identity Provider (IdP) product.

It is **in no way** the same class of software as Duende **IdentityServer** (or Keycloak, Auth0, Microsoft Entra ID, Okta). Those are commercial or full-stack IdP products. This repo is not a self-hosted IdentityServer replacement.

## What you get

Three separate systems (they do not collapse into one “identity platform”):

| Piece | Package family | Job |
| --- | --- | --- |
| Application sign-in | `Novolis.Security.Authentication.*` | Identifier + isolated Argon2id credential, browser session, lockout, optional `IMfaProvider` |
| Access-token mint | `Novolis.Security.OAuth.*` | Authorization Code + S256 PKCE, client credentials, rotating refresh, ES384 JWT with `cnf`, DPoP or mTLS thumbprint, revoke, discovery, JWKS |
| Tenant authorization | `Novolis.Security.Authorization.*` | Default-deny permissions, groups, roles, composite roles. Tenant is always explicit. OAuth scopes are not application permissions |

Crypto helpers (`PasswordHashing`, `Encryption`, `Cryptography`, `HaveIBeenPwned`, `Secrets`, `SecureText`) do not become an IdP by existing in the same repo.

**Token mint** means: after your host has an authenticated session, these packages can issue and validate **access tokens** for *your* APIs. They do not implement OpenID Connect as a login protocol: no ID Tokens as login, no userinfo, no OIDC hybrid/implicit, no federation to Google/Entra/SAML, no admin UI, no consent screen, no user-store product.

**Tenant authorization framework** means: given an `IdentityId`, a tenant, and a permission, decide allow or deny. It is not OAuth scopes, not a policy language, not ABAC, and not an IdP directory.

## What this is not

This is **not the same class of product** as Duende **IdentityServer**, Keycloak, Auth0, Microsoft Entra ID, Okta, or similar commercial / full-stack IdPs.

| Capability | Novolis.Security | Duende IdentityServer / typical commercial IdP |
| --- | --- | --- |
| Library you compose in a product host | Yes | Often a licensed product or hosted service |
| Issue OAuth **access** JWTs for first-party APIs | Yes (token mint) | Yes, among much else |
| OpenID Connect (ID Tokens, userinfo, `acr` / `amr`) | **No** | Yes — that is the IdP job |
| Federation to other IdPs (Google, Entra, SAML) | **No** | Yes |
| Admin UI, consent UI, user administration | **No** — host builds screens | Typical product surface |
| Dynamic client registration, PAR, JAR, CIBA, Device Code, Token Exchange | **No** | Typical IdP surface |
| Tenant default-deny groups / roles / permissions | Yes (separate Authorization family) | Usually a different product, or custom |
| Drop-in “IdentityServer replacement” | **No** | That *is* IdentityServer |

Do not drop this in as a “self-hosted IdentityServer replacement.” If you need an IdP, use an IdP.

`MapNovolisOAuth()` is a small authorization-server **protocol** surface for first-party apps (games, launchers, companion APIs, nano-SaaS). An optional `openid-configuration` alias still advertises **OAuth-only** metadata. Discovery is not an OpenID Provider.

## How the pieces compose

```text
Product host (HTTPS, PEM, durable stores, distributed cache, real MFA)
    ├── Authentication  — who signed in (session cookie your host sets)
    ├── OAuth           — mint and validate access JWTs for APIs
    └── Authorization   — may this IdentityId do this permission in this tenant?
```

Authorization never guesses tenant from identity. JWT `sub` is `IdentityId`. Credentials stay off the identity row. That isolation is deliberate; it is not an IdP user directory.

The three families stay separate on purpose. Authentication does not reference OAuth. Authorization does not reference OAuth. OAuth may use Authentication abstractions for `IdentityId`. That is a token mint plus tenant authz, not a single IdP assembly.

## When to use this vs an IdP

**Use this** when a Novolis product host needs first-party sign-in, API access tokens, and tenant-scoped permissions, and you are willing to own TLS, keys, stores, MFA, and UI.

**Use Duende IdentityServer (or Keycloak, Entra, Auth0, …)** when you need OpenID Connect login, federation, consent, userinfo, an IdP admin surface, or a supported commercial IdP.

## Host duties (the library will not do these)

- TLS, HSTS, reverse-proxy `X-Forwarded-For` trust
- Signing-key PEM custody (ephemeral keys are Development-only)
- Durable client/code/refresh/identity stores (in-memory throws outside Development unless you opt in)
- Distributed `ICacheStore` when more than one process shares lockout, MFA, or OAuth leases
- A real `IMfaProvider` when a second factor is required (`NoopMfaProvider` is the library default)
- Cookie flags (`Secure`, `HttpOnly`, `SameSite`) on the session cookie the **host** sets
- Account recovery, consent UI, email, user admin screens

See [owasp-security-evaluation.md](owasp-security-evaluation.md) for the library-level security sheet and the production checklist. See [design.md](design.md) for non-goals.

## Related

- [getting-started.md](getting-started.md)
- [REFACTORING_SPEC.md](../REFACTORING_SPEC.md) — end-state contract (still not an IdP)
- [Novolis.Security.OAuth](../src/Novolis.Security.OAuth/README.md)
- [Novolis.Security.Authentication](../src/Novolis.Security.Authentication/README.md)
- [Novolis.Security.Authorization](../src/Novolis.Security.Authorization/README.md)
