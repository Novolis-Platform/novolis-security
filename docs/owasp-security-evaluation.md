# OWASP security evaluation — novolis-security

| Field | Value |
| --- | --- |
| Date | 2026-09-30 (logger sinks, idle timeout, grant revoke, live key rotate, form_post) |
| Supersedes | Earlier 2026-09-30 sheet that still scored idle timeout, grant revoke, live rotation, form_post, and logging as Partial |
| Target | `novolis-security` libraries: Authentication, OAuth, Authorization, password hashing, encryption, cryptography, secrets, HIBP, SecureText |
| Version evaluated | Working tree on `main` after `ILogger` event sinks as default plus idle timeout, `RevokeGrantsAsync`, `SigningKeyRing.RotateAsync`, and `response_mode=form_post` |
| Evaluator | Maintainer review plus the automated suites below |
| Security check | **Passed** (selected ASVS 5.0.0 Level 2 library controls) |
| Overall | MFA is a product plug-in (`IMfaProvider`, default `NoopMfaProvider`). Sign-in failures share a cache-backed counter and disable the credential when the budget is spent. `ICacheStore` is in-memory for tests and a single process; a farm replaces it with a distributed store. Authentication and OAuth events default to `ILogger`. |

This is a library evaluation, not a hosted-product pentest. TLS, edge WAF, key custody, and the concrete MFA method (TOTP, WebAuthn, SMS) live in the executable host.

## 1. Scope

**In scope**

- `Novolis.Security.Authentication*` — identifier directory, isolated Argon2id credentials, browser sessions
- `Novolis.Security.OAuth*` — Authorization Code + S256 PKCE, client credentials, rotating refresh tokens, ES384 access tokens with `cnf`, DPoP, revoke, discovery, JWKS
- `Novolis.Security.Authorization*` — tenant-scoped default-deny permissions
- `Novolis.Security.PasswordHashing` — Argon2id PHC
- `Novolis.Security.Encryption` — AES-256-GCM
- `Novolis.Security.Cryptography` — CSPRNG, fixed-time compare, HKDF-SHA512
- `Novolis.Security.Secrets` / `WordLists`
- `Novolis.Security.HaveIBeenPwned` — Pwned Passwords range API as `IPasswordBreachChecker`
- `Novolis.Security.SecureText` — P-256 bundles, ECDH, HKDF-SHA256, AES-256-GCM

**Out of scope**

- OpenID Connect, SAML, dynamic client registration, PAR, JAR
- A built-in TOTP/WebAuthn/SMS implementation (the host supplies `IMfaProvider`)
- Host TLS, HSTS, WAF, HSM, SIEM

## 2. Methodology

Controls are scored only where they apply to a library.

1. [OWASP ASVS 5.0.0](https://asvs.dev/v5.0.0/) (May 2025) — V6 authentication, V7 session, V8 authorization, V9 self-contained tokens, V10 OAuth, V11 cryptography, V14 data protection, V16 logging. Level 2 is the bar for the identity core. Level 3 items are recorded; DPoP (10.4.14) is implemented. MFA (6.3.3) is a product `IMfaProvider`.
2. [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x00-header/).
3. Cheat sheets: [Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), [Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), [Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html), [JSON Web Token](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html).
4. [OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700) (RFC 9700), RFC 9449 DPoP, RFC 7638 JWK thumbprint, and RFC 7009 revocation.

| Score | Meaning |
| --- | --- |
| **Pass** | Implemented and covered by a test, or true by construction |
| **Partial** | Implemented with a residual risk called out in the findings |
| **Fail** | Missing or unsafe in the library itself |
| **N/A** | Host, product, or out of scope |

## 3. Executive summary

The morning 2026-09-30 sheet is stale. The gaps it locked in as current behavior are remedied:

- `RegisterAsync` rejects passwords shorter than 8 characters even if options try to lower the floor. `IPasswordBreachChecker` is required outside Development. Have I Been Pwned implements the checker; Authentication still does not reference that assembly.
- Sign-in failures increment `ICacheStore` (`auth:fail:cred:{reference}`). At `MaxSignInFailures` the credential is disabled and later attempts dummy-verify and fail closed, including the correct password. Unknown identifiers share an identifier-hash counter and the same `invalid_credentials` error.
- `IMfaProvider` runs after a correct password. The default is `NoopMfaProvider`. A product provider uses the same cache for challenges and one-time proofs. Registration does not require MFA (enrollment is a product step).
- `ICacheStore` lives on Authentication abstractions so Authentication and OAuth share one product cache. In-memory (`IsProcessLocal`) is for tests and a single process. A farm replaces it with Redis (or similar). `TryCreateAsync` leases refresh rotation and code consume against that same store.
- A second sign-in revokes every other live session. `DisableAsync` sets `IdentityRecord.Disabled`, revokes sessions, and notifies revocation sinks. Authorization denies a disabled identity before role expansion.
- `SignOutAsync` and `DisableAsync` invoke `IIdentityRevocation`. OAuth revokes every refresh family for that identity and writes an identity not-before into `ICacheStore`. Access tokens with `iat` at or before that cutoff fail `ValidateAsync`.
- Authorization-code replay returns `invalid_grant` and revokes the access-token `jti` and the refresh family recorded on the consumed code.
- Refresh rotation copies `FamilyExpiresUtc` from first issue and clamps `ExpiresUtc`. A refresh at or after the family cap is `invalid_grant`.
- Token attempts are limited per `client_id` and per remote IP. `TrustForwardedFor` is false by default.
- Issuance requires a DPoP ES256 proof (`typ` `dpop+jwt`) or an mTLS certificate thumbprint. Access tokens carry `cnf.jkt` or `cnf.x5t#S256`. `ValidateAsync` rejects a confirmation-bound token without a matching proof.
- Authentication and OAuth event sinks default to `ILogger` (`LoggerAuthenticationEventSink`, `LoggerEventStore`). A missing `ILoggerFactory` uses `NullLogger`. `AddNovolisOAuthEvents` replaces the OAuth logger with a host delegate. Production still throws on `NoopEventStore` and in-memory stores unless `AllowInMemoryStores` is set.
- Browser sessions have a 20-minute idle timeout (`SessionIdleTimeout`) on `ICacheStore` in addition to the 8-hour absolute lifetime.
- `RevokeGrantsAsync` is the library API for “sign out everywhere”: it revokes every browser session and notifies `IIdentityRevocation` (refresh families and access-token not-before). Product UIs bind to it; this library does not ship a screen.
- `SigningKeyRing.RotateAsync` installs a new ES384 current signer and keeps previous keys for validation and JWKS.
- `/oauth/authorize` accepts `response_mode=form_post` (auto-submit POST of `code`/`state`). Default remains query redirect. Discovery lists `query` and `form_post`.

What was already holding up is unchanged: Argon2id, AES-256-GCM, ES384-only JWT validation, exact redirect allow-list, S256 PKCE, credential/identity file isolation, default-deny tenant authorization.

## 4. Threat model

| Asset | Attacker | Impact if lost |
| --- | --- | --- |
| Argon2id password hash | Database dump | Offline cracking. The hash is not stored beside the email |
| Client secret PBKDF2-SHA512 hash | Database dump | Offline guessing of a low-entropy secret the host chose |
| Refresh token `{id}.{secret}` | Theft | New access tokens until rotation, reuse detection, family revoke, family cap, or identity sign-out |
| Authorization code `{id}.{secret}` plus PKCE verifier | Interception | One redemption. Replay revokes the first access `jti` and refresh family |
| ECDSA P-384 private PEM | Host compromise | Forge access tokens for this issuer |
| Access JWT | Theft | API access until `exp` only if the thief also has the DPoP key or matching client certificate |
| Token endpoint | Online guessing | Argon2 or PBKDF2 cost plus per-`client_id` and per-IP windows |
| Sign-in | Online guessing | Dummy Argon2 on misses, per-credential failure budget, credential disable |

Assumed host: HTTPS only, PEM supplied by the host, distributed `ICacheStore` when more than one process is used, `IPasswordBreachChecker` registered outside Development, real `IMfaProvider` when a second factor is required.

## 5. ASVS 5.0.0 (Level 2, selected)

### V6 — Authentication

| ID | Control | Score | Evidence |
| --- | --- | --- | --- |
| 6.2.1 | User passwords at least 8 characters | **Pass** | `RegisterAsync` rejects `"short"` / `"x"` with `password_too_short`. The floor is 8 even if options try to lower it |
| 6.2.5 | No composition rules | **Pass** | The hasher and registrar do not demand character classes |
| 6.2.8 | No truncation or case folding | **Pass** | Over-long passwords fail verify. NFC is applied on hash and verify. Case is preserved |
| 6.2.9 | At least 64 characters permitted | **Pass** | `MaxPasswordLength` default 1024 |
| 6.2.10 | No periodic password rotation | **Pass** | The library does not expire passwords |
| 6.2.4 / 6.2.12 | Denylist and breached-password check | **Pass** | `IPasswordBreachChecker` is called on register and password change. A missing checker throws outside Development. HIBP implements the checker in a separate assembly. Checker exceptions fail closed (`password_check_unavailable`) |
| 6.2.2 / 6.2.3 | Users can change password with current and new | **Pass** | `ChangePasswordAsync` dummy-verifies the current password, applies the same policy as register, replaces the hash, and revokes sessions and OAuth grants |
| 6.2.11 | Context-specific forbidden fragments | **Pass** | Identifier substring and `ForbiddenPasswordFragments` fail with `password_forbidden` |
| 6.3.1 | Anti-automation | **Pass** | Token endpoint: 30 attempts / minute / `client_id` and the same window per IP. Sign-in: `MaxSignInFailures` (default 5) on `ICacheStore`; at the cap the credential is disabled and later attempts fail closed with dummy Argon2 |
| 6.3.2 | No default accounts | **Pass** | No seeded root or admin credential |
| 6.3.3 | MFA or combined factors | **Pass** | `IMfaProvider` after a correct password. Default `NoopMfaProvider` for tests and single-factor hosts. Products replace it and use `ICacheStore` for challenges. A host that keeps the no-op on the public internet is choosing not to enforce a second factor |
| 6.3.4 | Consistent pathways | **Pass** | Password, implicit, and device grants are `unsupported_grant_type`. Public clients cannot use client credentials |
| 6.4.2 | No password hints or secret questions | **Pass** | `CredentialRecord` and `IdentityRecord` have no hint or KBA fields |
| 6.5.1 | MFA proofs one-time | **Pass** | Product `IMfaProvider` uses `ICacheStore.TryCreateAsync` so a proof cannot be replayed. Demonstrated by `SignIn_ProductMfa_RequiresProof_AndConsumesItOnce` |

### V7 — Session management

| ID | Control | Score | Evidence |
| --- | --- | --- | --- |
| 7.2.1 | Backend verification | **Pass** | Session id is an opaque reference looked up server-side |
| 7.2.2 | Dynamic tokens | **Pass** | Sessions, codes, and refresh secrets are generated per issuance |
| 7.2.3 | CSPRNG, at least 128 bits | **Pass** | Session id is 32 bytes from `RandomNumberGenerator` (asserted). Code and refresh secrets are 32 bytes |
| 7.2.4 | New session on authentication, previous session terminated | **Pass** | A second sign-in returns a different session id. The first session no longer authenticates |
| 7.3 | Timeouts | **Pass** | Session default 8 hours absolute plus 20-minute idle (`SessionIdleTimeout` on `ICacheStore`, refreshed on each successful lookup). Access 15 minutes. Authorization code 2 minutes. Refresh family cap is `RefreshTokenLifetime` from first issue |
| 7.4.1 | Logout blocks further use | **Pass** | `SignOutAsync` revokes that session id, every refresh family for the identity, and access tokens whose `iat` is at or before the identity cutoff |
| 7.4.2 | Disable or delete ends sessions | **Pass** | `DisableAsync` sets `Disabled`, revokes every session, notifies revocation sinks. `GetAuthenticatedIdentityAsync` returns null. Authorization denies before role expansion. Code redemption is `invalid_grant` |

### V8 — Authorization

| ID | Control | Score | Evidence |
| --- | --- | --- | --- |
| 8.2.1 | Function-level allow-list | **Pass** | Default deny. A role assignment is required. Unknown grants and unknown scopes fail closed. Disabled identities are denied even with a role |
| 8.2.2 | Object-level / BOLA | **Pass** | Refresh and revoke bind to the authenticated client. Role assignments do not cross tenants. Authorization codes are bound to `client_id` |
| 8.2.3 | Field-level / BOPLA | **Pass** | JWT `sub` is the identity id. Email and password are absent. Token requests that are not form bodies are rejected |
| 8.3 | Operation-level | **Pass** | Client credentials omit refresh tokens and have a null identity. Public clients are `unauthorized_client` for that grant. Client-credentials subjects are client ids and are unchanged by user sign-out |

### V9 — Self-contained tokens

| ID | Control | Score | Evidence |
| --- | --- | --- | --- |
| 9.1.1 | Signature checked before use | **Pass** | Tampered tokens fail `ValidateAsync` |
| 9.1.2 | Algorithm allow-list, no `none` | **Pass** | `ValidAlgorithms` is ES384 only. `alg=none` and HS256 are rejected |
| 9.1.3 | Keys from the issuer, not `jku` / `jwk` | **Pass** | Validation uses the process key ring |
| 9.2.1 | `nbf` and `exp` | **Pass** | Both required. Default clock skew 30 seconds. Identity not-before is an extra cutoff |
| 9.2.3 | Audience allow-list | **Pass** | `aud` must match `OAuthOptions.Audiences` |
| 9.2.2 | Token type and purpose | **Pass** | Access tokens use `typ` `at+jwt`. `ValidateAsync` rejects other types. DPoP proofs require `typ` `dpop+jwt` |

### V10 — OAuth and OIDC

| ID | Control | Score | Evidence |
| --- | --- | --- | --- |
| 10.4.1 | Exact redirect allow-list | **Pass** | Unregistered, prefix, and query-appended redirect URIs return 400 and do not redirect |
| 10.4.2 | Code single-use, and replay revokes issued tokens | **Pass** | Second redemption is `invalid_grant`. The access token from the first redemption fails `ValidateAsync`. The refresh family is revoked |
| 10.4.3 | Code lifetime ≤ 10 minutes | **Pass** | Default `AuthorizationCodeLifetime` is 2 minutes |
| 10.4.4 | No implicit, no password grant | **Pass** | `response_type` other than `code` is 400. Discovery omits `password` and `implicit` |
| 10.4.5 | Refresh rotation and reuse detection | **Pass** | Rotation invalidates the presented token. Reuse revokes the family. `ICacheStore.TryCreateAsync` leases rotation and code consume. In-memory is process-local by design; a farm supplies a distributed `ICacheStore` |
| 10.4.6 | PKCE S256, reject `plain` | **Pass** | Missing or `plain` challenges fail. The token request requires `code_verifier` |
| 10.4.7 | Dynamic client registration | **N/A** | Not implemented |
| 10.4.8 | Absolute refresh expiration | **Pass** | `FamilyExpiresUtc` is set at first issue to `now + RefreshTokenLifetime`, copied on rotation, and clamps `ExpiresUtc`. A refresh at or after the cap is `invalid_grant` |
| 10.4.9 | User can revoke refresh tokens | **Pass** | `/oauth/revoke` revokes the family after client authentication. `SignOutAsync`, `DisableAsync`, and `RevokeGrantsAsync` revoke every family for the identity and write an access-token not-before. Product UIs bind “sign out everywhere” to `RevokeGrantsAsync`; this library does not ship a screen |
| 10.4.10 | Confidential client authentication | **Pass** | Secret required. Basic and form `client_id` mismatch is `invalid_client`. Unknown and bad secrets share that error. A public client that presents a secret is rejected |
| 10.2.1 | PKCE or `state` against CSRF | **Pass** | PKCE S256 is mandatory. `state` is echoed when present and is not required |
| 10.4.14 | Sender-constrained access tokens | **Pass** | DPoP ES256 proofs or `cnf.x5t#S256` from a client certificate. Issuance with neither fails. `ValidateAsync` requires a matching proof and `ath`. Mismatch and missing proof fail |
| 10.3 | Resource server uses token claims | **Pass** | `ValidateAsync` requires `aud`, exposes `sub`, `scope`, and `client_id`, and requires a matching DPoP or certificate confirmation |

OIDC client and identity-provider sections are **N/A**. Discovery does not advertise a userinfo endpoint, and `/.well-known/openid-configuration` is absent unless the host opts into the alias.

### V11 — Cryptography

| ID | Control | Score | Evidence |
| --- | --- | --- | --- |
| 11.3.2 | Approved cipher | **Pass** | AES-256-GCM for string encryption and SecureText |
| 11.3.3 | Authenticated encryption | **Pass** | GCM tag. Tampered ciphertext and tampered AAD fail |
| 11.4 | Password hashing | **Pass** | Argon2id PHC. No MD5 or SHA-1 password storage. Verify refuses oversized `m` / `t` / `p` |
| 11.4 | Client secrets | **Pass** | PBKDF2-HMAC-SHA512, 210000 iterations, 16-byte salt, fixed-time compare |
| 11.5.1 | CSPRNG for non-guessable values | **Pass** | `RandomNumberGenerator` via `SecureRandom`. Not `System.Random` |
| 11.2 | Key inventory and agility | **Pass** | Algorithms are explicit. The host supplies PEM. `SigningKeyRing.RotateAsync` installs a new current signer and keeps previous keys for validation and JWKS. Ephemeral P-384 is refused outside Development |

HIBP uses SHA-1 because the Pwned Passwords range API defines the prefix that way. That hash is not a password store.

SecureText derives a pairwise AES-256 key with P-256 ECDH and HKDF-SHA256. Bundle signatures are checked before use.

### V14 — Data protection

| ID | Control | Score | Evidence |
| --- | --- | --- | --- |
| 14.2.1 | Secrets not in the query string | **Pass** | The token endpoint is POST form only. GET `/oauth/token` is 405. Authorization default is query (RFC 6749). `response_mode=form_post` returns an auto-submit POST of `code`/`state`. Discovery lists `query` and `form_post` |
| 14.2.2 | Sensitive responses not cached | **Pass** | Token and revoke responses set `Cache-Control: no-store` and `Pragma: no-cache` |
| 14.2.6 | Minimum data | **Pass** | Credential row is reference, hash, disabled, timestamps. Identity row holds the email and no password hash. JSON files do not combine the two |

### V16 — Logging

| ID | Control | Score | Evidence |
| --- | --- | --- | --- |
| 16.2.5 | No credentials in logs | **Pass** | Security events carry type, client id, identity id, grant, and error. They do not carry passwords, refresh secrets, or PEMs |
| 16.3.1 | Authentication outcomes logged | **Pass** | Default sinks are `LoggerAuthenticationEventSink` and `LoggerEventStore` (`ILogger`). Payloads are type, client id, identity id, grant, and error. A missing logger factory uses `NullLogger`. Production still refuses an explicit `NoopEventStore` unless `AllowInMemoryStores` |
| 16.3.2 | Failed authorization attempts logged | **Pass** | Default `LoggerAuthorizationEventSink`. Denies record type, tenant, identity, and permission id |
| 16.5.1 | Generic errors | **Pass** | Token errors are JSON `error` codes. They do not include stack traces, PEMs, or secrets |

## 6. OWASP API Security Top 10 (2023)

| API | Theme | Score | Notes |
| --- | --- | --- | --- |
| API1 | Broken object level authorization | **Pass** | Client binding on refresh, revoke, and authorization codes. Tenant binding on roles |
| API2 | Broken authentication | **Pass** | Strong token crypto, DPoP, registration policy, no password grant, sign-in lockout, MFA hook |
| API3 | Broken object property level authorization | **Pass** | No email in the JWT. JSON bodies on the token endpoint are rejected |
| API4 | Unrestricted resource consumption | **Pass** | Argon2 and PHC caps, authorization-code and password length caps, per-`client_id` and per-IP windows, per-credential sign-in budget |
| API5 | Broken function level authorization | **Pass** | Default deny. Unsupported grants fail closed. Public clients cannot take client credentials. Disabled identities cannot use assigned roles |
| API6 | Unrestricted sensitive flows | **Pass** | The token endpoint limiter is `client_id` and IP. Rotating `client_id` from one address is still `temporarily_unavailable` |
| API7 | SSRF | **Pass** | No URL fetch from client input. `jku` is not followed |
| API8 | Security misconfiguration | **Pass** | Ephemeral signing keys are Development-only. In-memory stores and the no-op sink throw outside Development unless `AllowInMemoryStores` |
| API9 | Improper inventory | **Pass** | Discovery lists authorization code, client credentials, refresh, `code`, and S256. It is not an OpenID Provider |
| API10 | Unsafe API consumption | **Pass** | HIBP uses k-anonymity. Range lookups throw unless the origin is `https://api.pwnedpasswords.com` |

## 7. Cheat sheets and RFC 9700

| Item | Score |
| --- | --- |
| Argon2id, 19 MiB, t=2, p=1, unique 16-byte salt, PHC | **Pass** |
| Unicode NFC before hash and verify | **Pass** |
| Verify-time caps (`m` ≤ 65536 KiB, `t` ≤ 12, `p` ≤ 16) | **Pass** |
| Pepper | **N/A** — host KMS if added |
| Deny `alg=none` and HMAC/RSA confusion | **Pass** |
| JWKS without private `d` | **Pass** |
| Short access lifetime (15 minutes) | **Pass** |
| Avoid ROPC and implicit | **Pass** |
| Exact redirect URI | **Pass** |
| PKCE S256 | **Pass** |
| Refresh rotation and reuse detection | **Pass** in one process with in-memory cache. **Pass** across processes when the product registers a distributed `ICacheStore` |
| Refresh cannot expand scope or audience | **Pass** |
| Issuer from options, not the Host header | **Pass** |
| Sender-constrained access tokens | **Pass** (DPoP ES256 or mTLS thumbprint) |
| Client authentication, Basic exclusive when present | **Pass** |

## 8. Findings

### Closed: F-02 — cache is a product implementation

- **Status:** Closed as a library gap. Documented as a host choice.
- **What:** `ICacheStore` is the shared product cache for lockout, MFA, rate limits, identity not-before, and refresh/code leases. `InMemoryCacheStore.IsProcessLocal` is true: that is correct for tests and a single process. A farm replaces the registration with a distributed backing store so every process sees the same counters and once-only gates. Repository `Lock` stays process-local because `IRepository` has no compare-and-swap; the lease on `ICacheStore` is the cross-process gate.

### Closed on the identity-core pass

| Id | Status |
| --- | --- |
| F-03 IP attempt limit | **Closed.** `oauth:rate:ip:{address}` uses the same window as the client-id counter. `TrustForwardedFor` is false by default; when set, only the left-most `X-Forwarded-For` is used |
| F-07 sender-constrained tokens | **Closed.** DPoP ES256 subset of RFC 9449, or `cnf.x5t#S256` from a client certificate. Stolen bearer use without the proof fails |
| F-08 in-memory production stores | **Closed.** Outside Development, process-local cache (`IsProcessLocal`) / in-memory client/code/refresh stores or an explicit `NoopEventStore` throw unless `AllowInMemoryStores`. The default event sink is `ILogger`, not no-op |
| F-11 registration policy | **Closed.** 8-character floor and `IPasswordBreachChecker`. Authentication does not reference HaveIBeenPwned |
| F-12 sessions and disable | **Closed.** Sign-in revokes other sessions. `DisableAsync` revokes sessions and sinks. Authorization denies disabled identities. A missing identity record still authorizes from roles |
| F-13 sign-out tokens | **Closed.** `IIdentityRevocation` revokes refresh families and writes an identity not-before. Client-credentials tokens whose subject is the client id are unchanged |
| F-14 code replay | **Closed.** Replay returns the consumed row, revokes that family, and denies that `jti` until `exp` |
| F-15 family cap | **Closed.** `FamilyExpiresUtc` is set once at first issue and copied on rotation |

### Closed since 2026-09-22

| Id | Status |
| --- | --- |
| F-01 password grant | **Closed.** `grant_type=password` is `unsupported_grant_type` |
| F-04 unknown scopes | **Closed.** `invalid_scope` |
| F-05 HIBP range-body logging | **Closed.** Debug log is the suffix count |
| F-06 Unicode NFC | **Closed.** Hash and verify both normalize Form C |
| F-09 disabled clients | **Closed.** `invalid_client` |
| F-10 SQLite `OAuthClient` | **Closed.** `StoredOAuthClient` packs lists. The SQLite reference scenario persists the client and completes the code flow |

## 9. Tests that back this sheet

Reference host: `tests/Novolis.Security.OAuth.Integration/ReferenceIdentityHost.cs`.

| Check | Where |
| --- | --- |
| JSON and SQLite: isolated credential file, 256-bit session, short-password reject, session replace, DPoP-bound code + S256, replay invalidates access token, sign-out invalidates JWT, disable vs redeem and authorization | `OwaspReferenceScenarioTests` |
| Short password, breached password, failure lockout, product MFA, logger defaults, idle timeout, `RevokeGrantsAsync`, password change, forbidden fragments, no KBA fields, production breach-checker guard | `AuthenticationIsolationTests` |
| Live signing-key rotate keeps previous `kid` valid; `RevokeGrantsAsync` invalidates access and refresh; `typ` `at+jwt`; resource-server `sub`/`scope`/`aud` | `OAuthTokenServiceTests` |
| Open redirect, prefix and query redirect, implicit `response_type`, optional `state`, `form_post` encoding, GET token 405, generic token errors, no-store, Host header, per-client and per-IP rate limit, production in-memory guard, DPoP mismatch | `OwaspHttpScenarioTests` |
| Denied authorization is recorded; default authorization sink is `ILogger` | `AuthorizationEngineTests` |
| Pwned Passwords origin pin | `HaveIBeenPwnedClientTest` |
| Refresh family absolute cap | `OAuthTokenServiceTests` |
| Authentication does not reference HIBP; OAuth and Authorization do not reference each other | `SecurityArchitectureTests` |
| `alg=none`, HS256, concurrent refresh | `OAuthRedTeamTests` |
| Password grant rejected, code replay, wrong verifier, scope and audience escalation, JWKS without `d` | `OAuthTokenServiceTests`, `OAuthAttackSurfaceTests` |
| Argon2 NFC, PHC bombs, AES-GCM tamper, SecureText AAD and bundle signature | Hasher, encryptor, and SecureText tests |
| Default deny, group grant, composite roles, cross-tenant | `AuthorizationEngineTests` |

## 10. Host production checklist

1. HTTPS only, with HSTS at the edge.
2. Set `OAuthOptions.Issuer` to the public HTTPS origin and set `Audiences` to the resource servers.
3. Provide a P-384 PKCS#8 PEM. Do not set `AllowEphemeralSigningKey` outside Development.
4. Replace in-memory stores. JSON and SQLite both complete the reference scenario. Do not set `AllowInMemoryStores` in production.
5. Call `AddNovolisPasswordBreachCheck()` (or another `IPasswordBreachChecker`) outside Development.
6. Keep the default `ILogger` sinks, or call `AddNovolisOAuthEvents` (or another `IEventStore`) if the host wants a custom observer. Do not register `NoopEventStore` in production.
7. Keep the identifier directory off the credential records.
8. Put a trusted reverse proxy in front if you set `TrustForwardedFor`. The library uses only the left-most `X-Forwarded-For` value.
9. Keep in-memory `ICacheStore` for tests and a single process. Replace it with a distributed cache before more than one process, pod, or app shares lockout, MFA, or OAuth leases.
10. Present DPoP proofs (or an mTLS client certificate) on token requests and resource requests.
11. Keep `NoopMfaProvider` only where a second factor is not required. Internet issuers replace `IMfaProvider`.

## 11. Verdict

| Area | Verdict |
| --- | --- |
| Password hashing | Pass |
| String encryption and SecureText | Pass |
| JWT mint and validate | Pass for ES384 with `cnf` |
| Authorization Code + S256 PKCE | Pass, including replay revocation |
| Refresh tokens | Pass; distributed `ICacheStore` when more than one process |
| Redirect binding | Pass |
| Store isolation | Pass |
| Registration policy | Pass |
| Session termination on re-auth, sign-out, and disable | Pass |
| Sign-in lockout | Pass |
| MFA | Pass as a product `IMfaProvider` (default no-op) |
| Sender-constrained access tokens | Pass (DPoP or certificate thumbprint) |
| SQLite as a client store | Pass |
| Fit as an OpenID Provider | No |

**Security check: Passed.** Selected ASVS 5.0.0 Level 2 library controls for this identity core are met. A hosted product still needs TLS, a distributed cache when it scales out, a registered breach checker outside Development, and a real `IMfaProvider` when a second factor is required. Event sinks already default to `ILogger`.

Re-run:

```powershell
dotnet test d:\novolis\novolis-security\tests\Novolis.Security.Unit\Novolis.Security.Unit.csproj -p:NovolisUseProjectReferences=true
dotnet test d:\novolis\novolis-security\tests\Novolis.Security.OAuth.Integration\Novolis.Security.OAuth.Integration.csproj -p:NovolisUseProjectReferences=true
```

Unit: 95 passed, 1 skipped network check. Integration: 4 passed.

## 12. References

- OWASP ASVS 5.0.0
- OWASP API Security Top 10 2023
- OWASP Password Storage, Authentication, Cryptographic Storage, and JWT cheat sheets
- RFC 6749, RFC 7009, RFC 7636, RFC 7638, RFC 8414, RFC 9449, RFC 9700
- [design.md](design.md)
