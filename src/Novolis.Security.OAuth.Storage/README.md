<!-- novolis-pkg-brand:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.svg" width="72" alt="Novolis"/>
  </a>
</p>
<!-- novolis-pkg-brand:end -->

# Novolis.Security.OAuth.Storage

`IRepository<T>` adapters for identity stores. The host chooses Json / LiteDB / SQLite / in-memory via `AddStorage`.

`ICredentialStore` still loads **only by `CredentialReference`**. Do not add email/username columns to `CredentialRecord` or query them here. Identifier lookup is a different system. Co-locating those fields with password hashes is a grave violation of minimum secure data-store design.

Username / `client_id` scans use `IRepository.All()` — acceptable for this limited library. Custom stores may add SQL indexes later. `client_id` is an OAuth client name, not a customer email.

## Install

```bash
dotnet add package Novolis.Security.OAuth.Storage
```

## Quick start

```csharp
services.AddNovolisOAuth(o => { /* ... */ });
services.AddStorage(b => b.AddSqliteProvider(...)); // host chooses provider
services.AddNovolisOAuthStorage();
```

Call `AddNovolisOAuthStorage` **after** `AddNovolisOAuth` so repository stores replace the in-memory defaults.

## Support

Pre-release (`2026.1.*` on GitHub Packages).
