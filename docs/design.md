# Design

Password hashing, encryption, and HaveIBeenPwned helpers.

Published docs: [https://novolis-platform.github.io/.github/novolis-security/](https://novolis-platform.github.io/.github/novolis-security/)

## Layer placement

Follow [library-boundaries](https://github.com/Novolis-Platform/novolis-governance/blob/main/docs/library-boundaries.md) for layer placement.

## Goals

- Keep public APIs documented and packable as `Novolis.*` on GitHub Packages (when applicable).
- Prefer BCL types and existing Novolis packages over parallel abstractions.
- Document restore and ProjectReference-mode builds without local NuGet folder feeds.

## Non-goals

- Local NuGet folder feeds or committed cross-repo `ProjectReference` into sibling checkouts.
- Avalonia package references outside `Novolis.Avalonia.*`.
- Upward spine dependencies (e.g. Math → Simulation).

## Packages

- `Novolis.Security.Cryptography` (CSPRNG, constant-time compare, HKDF-SHA512)
- `Novolis.Security.Encryption`
- `Novolis.Security.HaveIBeenPwned`
- `Novolis.Security.PasswordHashing`
- `Novolis.Security.Secrets`
- `Novolis.Security.OAuth.Abstractions` / `Novolis.Security.OAuth` / `.AspNetCore` / `.Storage`

Word lists (`Novolis.Security.WordLists`, internal) are process-wide `IEnumerable<string>` singletons (`Type.Instance`).

## Credential store isolation

`ICredentialStore` is a **credential vault**, not a user directory.

- Allowed on `CredentialRecord`: opaque `CredentialReference`, Argon2id password hash, disabled flag, timestamps.
- Forbidden on `CredentialRecord` (and on the same database/backup/export): email, username, phone, display name, handle hashes of those identifiers.

Placing username/email behind the same auth as the password hash is a **grave violation of minimum secure data-store design**. Identifier lookup must live in a completely different system that maps those values to `CredentialReference`. The OAuth password grant then authenticates by `CredentialReference` + password only.

## Topics

- `dotnet`
- `security`
- `novolis`
- `owasp`

See also: [owasp-security-evaluation.md](owasp-security-evaluation.md).
