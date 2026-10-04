# novolis-security documentation

Token mint, tenant authorization, password hashing, encryption, and HaveIBeenPwned helpers. **Not a commercial Identity Provider** — see [what-this-is.md](what-this-is.md).

Published docs: [https://novolis-platform.github.io/.github/novolis-security/](https://novolis-platform.github.io/.github/novolis-security/)

## Guides

| Doc | What it covers |
| --- | --- |
| [what-this-is.md](what-this-is.md) | Token mint + tenant authz framework vs Duende IdentityServer / full IdPs |
| [getting-started.md](getting-started.md) | Install, restore from GitHub Packages, first use |
| [design.md](design.md) | Goals, layer placement, non-goals, credential store isolation |
| [owasp-security-evaluation.md](owasp-security-evaluation.md) | OWASP ASVS 5.0.0 / API Top 10 / OAuth BCP evaluation of identity, hashing, and crypto libraries |
| [release.md](release.md) | CalVer publish and package list |

## Packages

| Package | Role |
| --- | --- |
| `Novolis.Security.Cryptography` | Helpers |
| `Novolis.Security.Encryption` | Helpers |
| `Novolis.Security.HaveIBeenPwned` | Helpers |
| `Novolis.Security.OAuth.Client` | Outbound Novolis-issuer caller |
| `Novolis.Security.PasswordHashing` | Helpers |
| `Novolis.Security.Secrets` / `SecureText` | Helpers |
| `Novolis.Security.Authentication.*` | Application sign-in (not an IdP) |
| `Novolis.Security.OAuth.*` | Access-token mint (not IdentityServer) |
| `Novolis.Security.Authorization.*` | Tenant authz framework (not OAuth scopes) |

## More

- [Org docs catalog](https://novolis-platform.github.io/.github/)
- [Repository README](../README.md)
- [Governance](https://github.com/Novolis-Platform/novolis-governance)

