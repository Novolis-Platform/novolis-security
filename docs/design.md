# Design

Password hashing, encryption, HaveIBeenPwned helpers, and the Authentication / OAuth / Authorization stack.

Published docs: [https://novolis-platform.github.io/.github/novolis-security/](https://novolis-platform.github.io/.github/novolis-security/)

The end-state contract is [REFACTORING_SPEC.md](../REFACTORING_SPEC.md).

## Layer placement

Follow [library-boundaries](https://github.com/Novolis-Platform/novolis-governance/blob/main/docs/library-boundaries.md) for layer placement.

## Goals

- Keep public APIs documented and packable as `Novolis.*` on GitHub Packages.
- Prefer BCL types and existing Novolis packages over parallel abstractions.
- Document restore and ProjectReference-mode builds without local NuGet folder feeds.
- Keep Authentication, OAuth, and Authorization as separate systems.

## Non-goals

- Local NuGet folder feeds or committed cross-repo `ProjectReference` into sibling checkouts.
- Avalonia package references outside `Novolis.Avalonia.*`.
- Password grant, OpenID Connect, SAML, nested groups, or negative authorization rules.

## Packages

- `Novolis.Security.Cryptography`
- `Novolis.Security.Encryption`
- `Novolis.Security.HaveIBeenPwned`
- `Novolis.Security.PasswordHashing`
- `Novolis.Security.Secrets`
- `Novolis.Security.Authentication.*`
- `Novolis.Security.OAuth.*`
- `Novolis.Security.Authorization.*`

## Credential store isolation

The credential vault is not a user directory.

- Allowed on `CredentialRecord`: opaque `CredentialReference`, password hash, disabled flag, timestamps.
- Forbidden on credential records: `IdentityId`, email, username, phone, display name, tenant, group, or role data.

`IdentityId` is the JWT subject. `CredentialReference` never becomes a public identifier.

## Authorization

Authorization is tenant-scoped. Groups contain identities. Roles contain permissions. Composite roles contain roles and must remain acyclic.

OAuth scopes are not application permissions.
