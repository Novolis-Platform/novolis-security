# Getting started

Password hashing (Argon2id), AES-256-GCM encryption, HaveIBeenPwned helpers, and the Authentication / OAuth / Authorization stack.

Published guide: [https://novolis-platform.github.io/.github/novolis-security/](https://novolis-platform.github.io/.github/novolis-security/)

## Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download)
- GitHub Packages auth for `Novolis.*` (see [nuget-only-policy](https://github.com/Novolis-Platform/novolis-governance/blob/main/docs/nuget-only-policy.md))

Configure GPR once from a sibling `novolis-governance` checkout:

```powershell
pwsh -File d:\novolis\novolis-governance\scripts\configure-gpr-user-nuget.ps1
```

## Install

```bash
dotnet add package Novolis.Security.Encryption
```

Local multi-repo iteration uses ProjectReference mode via `d:\novolis\Novolis.Platform.slnx` — never a local NuGet folder feed.

## Next

- [REFACTORING_SPEC.md](../REFACTORING_SPEC.md) — Authentication, OAuth, and Authorization end-state
- [design.md](design.md) — layer placement and non-goals
- [owasp-security-evaluation.md](owasp-security-evaluation.md) — OWASP ASVS 5.0.0 evaluation of identity, hashing, and crypto libraries
- [release.md](release.md) — publish cadence
- [Org docs catalog](https://novolis-platform.github.io/.github/)
