# OWASP security evaluation — novolis-security

| Field | Value |
| --- | --- |
| Date | 2026-09-22 |
| Target | `novolis-security` libraries (IDP, hashing, encryption, cryptography, secrets, HIBP, SecureText) |
| Version evaluated | Working tree on `main` (CalVer `2026.1.*`) |
| Evaluator | Maintainer review + automated red-team suite |
| Security check | **Failed** |
| Overall | Checklist is **Failed** (ROPC, no Unicode NFC, bearer tokens without sender constraint). Crypto and JWT validation are otherwise a conditional pass for a *limited first-party JWT IDP* — not a replacement for a full OpenID Provider |
| Tests | 94 passed, 1 skipped (HIBP live network) in `tests/Novolis.Security.Unit` |

This report is a library evaluation, not a hosted-product pentest. TLS, reverse proxies, key custody, and account directories live in the **executable host**.

## 1. Scope and intent

**In scope**

- `Novolis.Security.Idp*` — ES384 access tokens, Argon2id credentials, rotating refresh tokens, `/oauth/token`, `/oauth/revoke`, JWKS, discovery
- `Novolis.Security.PasswordHashing` — Argon2id PHC
- `Novolis.Security.Encryption` — AES-256-GCM
- `Novolis.Security.Cryptography` — CSPRNG, fixed-time compare, HKDF-SHA512
- `Novolis.Security.Secrets` / `WordLists` — passphrase and charset secrets
- `Novolis.Security.HaveIBeenPwned` — Pwned Passwords range API
- `Novolis.Security.SecureText` — device identity and pairwise session keys

**Out of scope (by design)**

- Authorization-code + PKCE, OIDC hybrid/implicit, federation, userinfo, consent UI
- IdentityServer / Duende / OpenIddict feature parity
- Email/username directory (forbidden on `IdpAccount`; see [design.md](design.md))
- Host TLS, HSTS, WAF, SIEM, HSM

The IDP is a **first-party token mint** for confidential clients. The resource-owner password grant takes an already-resolved `AccountId` GUID, not a login name.

## 2. Methodology

Controls are scored against four public sources, applied only where they fit a library (not a full web app):

1. **[OWASP ASVS 4.0.3](https://owasp.org/www-project-application-security-verification-standard/)** — chapters 2 (authn), 3 (session), 6 (crypto), 8 (data protection), 9 (comms), 14 (config). Level 2 is the bar for the IDP core.
2. **[OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x00-header/)** — API1–API10.
3. **Cheat sheets:** [Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), [Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), [JSON Web Token](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html), [Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html).
4. **[OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700)** (RFC 9700) for grant and refresh-token behaviour.

Scoring:

| Score | Meaning |
| --- | --- |
| **Pass** | Control is implemented and covered by tests or obvious by construction |
| **Partial** | Implemented with documented residual risk or host duty |
| **Fail** | Missing or unsafe in the library itself |
| **N/A** | Host / product / out-of-scope for this MVP |

Severity for findings: **Critical / High / Medium / Low / Info**.

## 3. Executive summary

Cryptography and JWT validation are in good shape: Argon2id (OWASP 2024 first recommendation), AES-256-GCM, ES384-only validation, public JWKS, rotating hashed refresh secrets, dummy Argon2 verify to blunt user enumeration, and a red-team suite that exercises alg=none, HMAC confusion, RS256/ES256, `jku` injection, refresh reuse, and scope elevation.

The largest *inherent* risk is the **resource-owner password credentials (ROPC)** grant, which RFC 9700 discourages. It is accepted here because the IDP is first-party, confidential-client-only, and authenticates by opaque `AccountId` rather than email. Hosts that need a public or third-party login must not stretch this library into an OpenID Provider.

The largest *operational* risk is **multi-instance refresh rotation**: reuse detection is process-local (`SemaphoreSlim`). A single-process host is safe; a farm needs a transactional store.

## 4. Threat model (library)

| Asset | Attacker | Impact if lost |
| --- | --- | --- |
| Argon2id password / client-secret hashes | DB dump | Offline cracking; **must not** also yield emails (store isolation) |
| Refresh token `{id}.{secret}` | Theft / XSS on client | New access tokens until rotation or family revoke |
| ECDSA P-384 private PEM | Host compromise | Forge any access token for the issuer |
| Access JWT | Theft | API access until `exp` (default 15 minutes) |
| Token endpoint | Online guessing | Mitigated by Argon2 cost + 30 req/min/IP |

Assumed host: HTTPS only, PEM not in source control, in-memory stores only for tests/dev, identifier directory is a separate system.

## 5. OWASP ASVS 4.0.3 (Level 2, selected)

### V2 — Authentication

| ID | Control | Score | Evidence |
| --- | --- | --- | --- |
| 2.1.1 | User identifier not the password | **Pass** | `IdpAccount` has no email/username; password grant uses `AccountId` |
| 2.1.7–2.1.9 | Password length limits | **Pass** | `MaxPasswordLength` default 1024; oversize verify returns false (DoS guard) |
| 2.2.1 | Anti-automation on login | **Partial** | Fixed-window 30/min **per IP** on `POST /oauth/token`; no per-account lockout, captcha, or backoff |
| 2.4.1 | Approved one-way function | **Pass** | Argon2id PHC; no PBKDF2/legacy verify |
| 2.4.2 | Salt ≥ 32 bits, unique | **Pass** | 16-byte CSPRNG salt per hash |
| 2.4.3 | Iterated work factor | **Pass** | Defaults m=19456 KiB, t=2, p=1 (OWASP 2024 first recommendation) |
| 2.4.5 | Constant-time compare | **Pass** | `ConstantTime.Equals` on derived Argon2 output and refresh SHA-512 |
| 2.5.2 | No username enumeration | **Pass** | Unknown account, bad password, and disabled account all `invalid_grant`; dummy Argon2 hash on misses |
| 2.5.4 | No default passwords in code | **Pass** | Dummy hash is a timing pad, not a login |
| 2.7 | Recovery / MFA | **N/A** | Out of library scope |
| 2.10 | Service authentication | **Pass** | Confidential clients only; public clients `unauthorized_client`; Basic vs form `client_id` mismatch → `invalid_client` |

### V3 — Session (tokens)

| ID | Control | Score | Evidence |
| --- | --- | --- | --- |
| 3.2.1 | Session token CSPRNG | **Pass** | Refresh secret 32 bytes `SecureRandom`; access JWT `jti` is UUID v7 |
| 3.2.2 | Tokens not in URL | **Pass** | POST form only; GET `/oauth/token` is 405 |
| 3.3 | Logout / revoke | **Pass** | `/oauth/revoke` authenticates the client, revokes the refresh **family** (RFC 7009 unknown → 200) |
| 3.3.2 | Idle / absolute timeout | **Partial** | Access default 15 min; refresh default 7 days; no idle timeout distinct from `exp` |
| 3.5 | Token generation | **Pass** | ES384; `ValidAlgorithms` is ES384-only; `RequireSignedTokens` |
| 3.7 | Defenses against session attacks | **Pass** | Refresh rotation + reuse detection; concurrent refresh serialized in-process |

### V6 — Stored cryptography

| ID | Control | Score | Evidence |
| --- | --- | --- | --- |
| 6.2.1–6.2.2 | Approved algorithms | **Pass** | Argon2id, AES-256-GCM, ES384 (P-384), HKDF-SHA512, SHA-512 for refresh-at-rest |
| 6.2.4 | Random generator | **Pass** | `RandomNumberGenerator` via `SecureRandom` — not `System.Random` |
| 6.2.5 | Nonce uniqueness | **Pass** | 12-byte GCM nonce per encrypt |
| 6.2.6 | Authenticated encryption | **Pass** | AES-GCM; tampered ciphertext throws `CryptographicException` |
| 6.2.7 | Keys not hard-coded | **Partial** | Library has no production keys; host **must** supply PEM (`AllowEphemeralSigningKey` forbidden outside Development) |
| 6.3 | Secret management | **Partial** | Refresh secrets stored as SHA-512; PEM handling is host duty |
| 6.4 | In-memory secrets | **Partial** | Refresh secret zeroed after hash; password bytes are not zeroed after Argon2 (Konscious API takes `byte[]`) |

### V8 — Data protection

| ID | Control | Score | Evidence |
| --- | --- | --- | --- |
| 8.2.1 | Sensitive data minimized | **Pass** | Credential row is `Id` + hash + disabled + timestamp; JWT `sub` is AccountId, not email |
| 8.2.2 | No secrets in logs | **Partial** | IDP does not log passwords. HIBP client logs the **full range API body** at Information (see F-05) |
| 8.3.4 | Sensitive data not in GET | **Pass** | Token endpoint is POST + `application/x-www-form-urlencoded` only |
| 8.3.5 | Cache-Control on sensitive responses | **Pass** | Token and revoke: `Cache-Control: no-store`, `Pragma: no-cache` |

### V9 — Communication

| ID | Control | Score | Evidence |
| --- | --- | --- | --- |
| 9.1 | TLS | **N/A** | Host must terminate TLS. Issuer default is `https://idp.novolis.local` as a hint, not enforcement |
| 9.2 | HTTP header injection / Host header | **Pass** | Discovery `issuer` comes from `IdpOptions`, not `Host` |

### V14 — Configuration

| ID | Control | Score | Evidence |
| --- | --- | --- | --- |
| 14.1 | Build / deploy | **Pass** | NuGet-only restore; no local folder feeds |
| 14.2 | HTTP security headers | **N/A** | Host (HSTS, CSP). Library sets no-store on tokens |
| 14.4 | Unwanted HTTP methods | **Pass** | Token is POST-only; PUT/GET rejected |
| 14.5.2 | CORS | **Pass** | No wildcard `Access-Control-Allow-Origin` from the IDP mapping |

## 6. OWASP API Security Top 10 (2023)

| API | Theme | Score | Notes |
| --- | --- | --- | --- |
| API1 | Broken object level authorization | **Pass** | Refresh and revoke bind to authenticated `client.Id`; stolen refresh cannot be used by another client |
| API2 | Broken authentication | **Partial** | Strong token crypto; ROPC remains an anti-pattern (accepted, mitigated). No MFA in library |
| API3 | Broken object property level authorization | **Pass** | JWT has no email; mass-assignment JSON body on token endpoint is rejected (form only) |
| API4 | Unrestricted resource consumption | **Partial** | Argon2 caps (password length, PHC m/t/p); token rate limit 30/min/IP; PHC bomb test. Argon2 is still expensive — that is the point |
| API5 | Broken function level authorization | **Pass** | Unsupported grants (`authorization_code`, device, jwt-bearer, token-exchange) fail closed. Discovery does not advertise an authorization endpoint |
| API6 | Unrestricted access to sensitive business flows | **Partial** | Password grant is the sensitive flow; rate limit is IP-scoped only |
| API7 | Server-side request forgery | **Pass** | No URL fetch from client input. `jku` in a JWT is not followed; validation uses the process key ring |
| API8 | Security misconfiguration | **Partial** | Ephemeral signing key blocked outside Development. Hosts can still ship in-memory stores or skip HTTPS |
| API9 | Improper inventory | **Partial** | Discovery lists the three grants and ES384. This is not a full OIDC OP — do not list it as one in a product catalog |
| API10 | Unsafe API consumption | **Partial** | HIBP uses k-anonymity (5-char SHA-1 prefix). Host must pin `https://api.pwnedpasswords.com`. Client logs the range body (F-05) |

## 7. Cheat-sheet and OAuth BCP checklist

### Password storage (OWASP)

| Item | Score |
| --- | --- |
| Argon2id with OWASP 19 MiB / t=2 / p=1 | **Pass** |
| Unique salt, PHC encoding | **Pass** |
| No SHA-1/MD5 for storage | **Pass** |
| Verify-time caps on attacker-controlled `m`/`t` | **Pass** (`MaxVerifyMemoryKiB=65536`, `MaxVerifyIterations=12`, p≤16) |
| Unicode NFC before hash | **Fail** (Low) — NFC vs NFD of the same character will not match (F-06) |
| Pepper | **N/A** — optional; would live in host KMS if added |

### JWT (OWASP)

| Item | Score |
| --- | --- |
| Deny `alg=none` | **Pass** (tested) |
| Deny algorithm confusion (HS256 with public key, RS256, ES256) | **Pass** (tested) |
| Explicit `ValidAlgorithms` | **Pass** (`EcdsaSha384` only) |
| Validate `iss`, `aud`, `exp`, signature | **Pass** |
| JWKS without private `d` | **Pass** (endpoint projects x/y/crv only) |
| Do not embed PII or passwords in JWT | **Pass** (tested) |
| Short access lifetime | **Pass** (15 minutes default) |
| Encrypted JWT (JWE) | **N/A** — signed Bearer is the MVP; TLS is the confidentiality layer |

### OAuth 2.0 Security BCP (RFC 9700)

| Item | Score |
| --- | --- |
| Sender-constrained access tokens (DPoP / mTLS) | **Fail** (Info) — bearer tokens; host network isolation required (F-07) |
| Avoid ROPC | **Partial** — grant exists; confidential + AccountId only (F-01) |
| Avoid implicit grant | **Pass** — unsupported |
| Refresh rotation + reuse detection | **Pass** in-process; **Partial** multi-instance (F-02) |
| Refresh cannot expand scope | **Pass** — original scope stored on `IdpRefreshToken` (tested) |
| Exact redirect URI | **N/A** — no authorize endpoint |
| PKCE | **N/A** — no authorize endpoint |
| Mix-up / issuer injection | **Pass** — issuer from options, not Host header |
| Client authentication | **Pass** — secret required; Basic exclusive when present |

## 8. Findings

### F-01 — Resource-owner password grant (accepted risk)

- **Severity:** High (inherent), mitigated to Medium in this design
- **ASVS / BCP:** API2, RFC 9700 §2.4
- **What:** `grant_type=password` is online password verification at the token endpoint. Phishing and credential-stuffing are easier than with code+PKCE.
- **Mitigations in tree:** confidential clients only; RFC `username` is an `AccountId` GUID (`TryParseExact` D/N); identifier directory is a different system; dummy Argon2; IP rate limit; same `invalid_grant` for miss/wrong/disabled.
- **Host:** Do not expose this grant to public SPA/native apps. Put HIBP checks in the **directory** at password-set time, not in the IDP.

### F-02 — Refresh reuse detection is process-local

- **Severity:** Medium
- **What:** `IdpTokenService` uses `SemaphoreSlim` around rotation. Two nodes can both accept the same refresh token if the store `Upsert` is not transactional.
- **Host:** One issuer process, or a store with compare-and-swap / serializable transaction on `IdpRefreshToken` (check `RevokedUtc` in the same write).

### F-03 — Rate limit is IP-only

- **Severity:** Medium
- **What:** 30 requests / minute / `RemoteIpAddress`. Behind a proxy without `UseForwardedHeaders`, every client shares `unknown` or the proxy IP (false 429s) **or** a misconfigured forwarded-for trust lets an attacker rotate source IPs.
- **Host:** Configure known proxy forwards; consider an additional per-`AccountId` / per-`client_id` limiter at the edge.

### F-04 — Password grant drops unknown scopes instead of failing

- **Severity:** Low
- **What:** `TryGrantScopes` silently intersects with the client allow-list (`api admin` → `api`). Refresh is strict (`invalid_scope` if any requested scope was not originally granted).
- **Recommendation:** Fail password/client-credentials with `invalid_scope` when any requested token is unknown (align with RFC 6749 SHOULD).

### F-05 — HIBP client logs the range response

- **Severity:** Low
- **Where:** `HaveIBeenPwnedClient` `LogInformation("Response: {Response}", response)`
- **What:** The body is a list of SHA-1 suffixes, not the password, but it is high-volume and inappropriate at Information.
- **Recommendation:** Log status/count only; never the range payload.

### F-06 — No Unicode normalization on passwords

- **Severity:** Low
- **What:** Hashing is UTF-8 of the raw string. NFC `é` and NFD `e + combining acute` are different passwords.
- **Recommendation:** Document “hash the bytes the client sent”; or NFC-normalize once at the directory before the IDP.

### F-07 — Bearer access tokens (no sender constraint)

- **Severity:** Info
- **What:** A stolen access JWT works until `exp`. No DPoP, mTLS, or token binding.
- **Host:** Short lifetime (already 15 min), TLS, and treat tokens like session cookies (no localStorage on a public web origin if that origin is untrusted).

### F-08 — In-memory stores are not a production vault

- **Severity:** Info (misconfiguration)
- **What:** `AddNovolisIdp` registers in-memory stores. `AddNovolisIdpStorage` swaps in `IRepository<T>`.
- **Host:** Production must call storage + persist signing PEM. Ephemeral P-384 is Development-only and already throws otherwise.

### F-09 — `IdpClient` has no disabled flag

- **Severity:** Low
- **What:** Compromised clients must be deleted or have `SecretHash` rotated. There is no `Disabled` on the client row (accounts do have it).

## 9. What the red-team suite already proved

Source: `tests/Novolis.Security.Unit/IdpRedTeamTests.cs`, `IdpAttackSurfaceTests.cs`, plus hasher/encryptor tests.

| Attack | Result |
| --- | --- |
| Email as `username` | `invalid_grant`, not looked up |
| Empty GUID username | `invalid_grant` |
| JSON / multipart / query-string token | 400 |
| GET/PUT token | 405 |
| Missing / wrong client secret | `invalid_client` (same error as unknown client) |
| Public client | `unauthorized_client` |
| Disabled account / empty password | `invalid_grant` |
| Argon2 PHC bomb (`m=999999`) | verify false, no huge allocation |
| Grant type case (`Password`) | `unsupported_grant_type` |
| Refresh from another client | `invalid_grant` |
| Access token as refresh | `invalid_grant` |
| Truncated refresh secret | `invalid_grant` |
| Expired access JWT (clock skew 0) | invalid |
| `alg=none`, HS256 confusion, RS256, ES256, `jku` | invalid |
| Tampered payload | invalid |
| JWKS contains `d` | false |
| `sub` is AccountId, no `@` | true |
| Basic vs form client mix-up | `invalid_client` |
| Refresh after disable / revoke | `invalid_grant` |
| Refresh scope escalation | `invalid_scope` |
| Concurrent refresh | exactly one success |
| Rate limit | 429 |
| Host header on discovery | issuer unchanged |
| CORS `*` | absent |
| Null-byte form | 400, not 500 |
| AES-GCM bit flip | `CryptographicException` |

## 10. Host production checklist

Do this in the executable, not in the library:

1. HTTPS only; HSTS at the edge.
2. Set `IdpOptions.Issuer` to the public HTTPS origin; set `Audiences`.
3. Provide P-384 PKCS#8 PEM (`SigningKeyPem`) or a signing-key store with private material. Never `AllowEphemeralSigningKey` in production.
4. `AddNovolisIdpStorage` + durable `IRepository<T>` — not in-memory.
5. Keep the identifier directory **off** the credential database (email/username ≠ password hash).
6. Forwarded headers only from trusted proxies so the 30/min limiter keys the real client IP.
7. Rotate PEM on a planned cadence; keep old public keys in JWKS until access tokens expire.
8. Run HIBP (or similar) at **password change** in the directory, not on every token request.
9. If more than one issuer replica: transactional refresh upsert (see F-02).

## 11. Verdict

| Area | Verdict |
| --- | --- |
| Password hashing | Pass (ASVS L2 crypto) |
| String encryption | Pass |
| JWT mint/validate | Pass for ES384 bearer |
| Refresh tokens | Pass single-process; Partial multi-instance |
| HTTP token surface | Pass for the limited grant set |
| Store isolation | Pass (by construction + tests) |
| HIBP helper | Partial (k-anonymity yes; noisy logging) |
| Fit as IdentityServer replacement | **No** — and that is intentional |

**Security check: Failed.** Do not treat this library set as ASVS L2 complete. Crypto and JWT validation are strong enough to ship a first-party confidential-client IDP after the host checklist, but ROPC (F-01), process-local refresh locking (F-02), IP-only rate limits (F-03), and missing sender-constrained tokens (F-07) keep the named security check **Failed** until they are closed or explicitly accepted in a product threat model. Do not market it as OIDC. Track F-02 before horizontal scale; F-05 is a quick logging fix; F-04 is a consistency cleanup.

Re-run:

```powershell
dotnet test d:\novolis\novolis-security\tests\Novolis.Security.Unit\Novolis.Security.Unit.csproj -p:NovolisUseProjectReferences=true
```

## 12. References

- OWASP ASVS 4.0.3
- OWASP API Security Top 10 2023
- OWASP Password Storage / Authentication / JWT cheat sheets
- RFC 6749, RFC 7009, RFC 7519, RFC 9700
- [design.md](design.md) — credential store isolation
