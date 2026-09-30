<!-- novolis-pkg-brand:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.svg" width="72" alt="Novolis"/>
  </a>
</p>
<!-- novolis-pkg-brand:end -->

# Novolis.Security.OAuth.Storage

`IRepository<T>` adapters for OAuth clients, authorization codes, refresh tokens, and signing keys. List and identity fields are packed into SQLite-safe scalar rows.

Rotation and one-time code consumption are process-local atomic. Multi-instance hosts must supply a transactional store if they require distributed compare-and-swap.

## Install

```bash
dotnet add package Novolis.Security.OAuth.Storage
```

## Quick start

```csharp
services.AddNovolisOAuthStorage();
```

## Support

Pre-release (`2026.1.*` on GitHub Packages).
