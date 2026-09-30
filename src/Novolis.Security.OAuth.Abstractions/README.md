<!-- novolis-pkg-brand:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.svg" width="72" alt="Novolis"/>
  </a>
</p>
<!-- novolis-pkg-brand:end -->

# Novolis.Security.OAuth.Abstractions

Contracts for **limited-scope** first-party identity / authentication: JWT issuance stores, persistable entities (`IHasId`), and token request/result types.

This is not an OAuth host, IdentityServer, Duende, or OpenIddict. No authorization-code UI, federation, or userinfo. A full OAuth executable composes these packages with TLS, directories, and edge limits.

## Credential store isolation (non-negotiable)

`CredentialRecord` / `ICredentialStore` hold **`CredentialReference` + password hash + metadata only**.

Putting username, email, phone, or any customer identifier **behind the same authentication boundary as the password hash** (same table, same database, same backup, same export) is a **grave violation of minimum secure data-store design**. A leaked credential store must not also be a customer directory.

Identifier lookup is a **different system**, keyed by `CredentialReference`. The password grant accepts an already-resolved `CredentialReference` — never an email string.

## Install

```bash
dotnet add package Novolis.Security.OAuth.Abstractions
```

**Prerequisites:** [.NET 10 SDK](https://dotnet.microsoft.com/download) (`net10.0`).

## Quick start

Implement the store contracts below, or compose the in-memory and storage
adapters from the related identity packages.

## What to implement

| Store | Lookup |
|-------|--------|
| `ICredentialStore` | `CredentialReference` only (no identifier columns) |
| `IClientStore` | `client_id` |
| `IRefreshTokenStore` | Refresh id (`Guid`) + family id |
| `IKeyStore` / `ISigningKeyStore` | Active keys / `kid` |
| `ICacheStore` | Rate-limit counters and rotation leases |
| `IEventStore` | Optional grant observations (default no-op) |
| `ITokenService` | Issue / revoke |

Entities implement `Novolis.Storage.Abstractions.IHasId` so `IRepository<T>` can persist them. Wire adapters via `Novolis.Security.OAuth.Storage`, or use the in-memory stores in `Novolis.Security.OAuth`.

## Related packages

| Package | When to use |
|---------|-------------|
| `Novolis.Security.OAuth` | Issuer, hasher, in-memory stores |
| `Novolis.Security.OAuth.AspNetCore` | `/oauth/token`, JWKS, discovery |
| `Novolis.Security.OAuth.Storage` | `IRepository<T>` adapters |

## More documentation

- [Getting started](https://github.com/Novolis-Platform/novolis-security/blob/main/docs/getting-started.md)
- [Design](https://github.com/Novolis-Platform/novolis-security/blob/main/docs/design.md)

## Support

Pre-release (`2026.1.*` on GitHub Packages).
