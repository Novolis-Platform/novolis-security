<!-- novolis-pkg-brand:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.svg" width="72" alt="Novolis"/>
  </a>
</p>
<!-- novolis-pkg-brand:end -->

# Novolis.Security.Authorization.Storage

`IRepository<T>` adapters for tenant-scoped groups, memberships, custom roles, assignments, and authorization versions.

Call after `AddNovolisAuthorization` and `AddStorage`. The host should wrap `IRoleStore` with the core validating store when accepting tenant-defined roles.

## Install

```bash
dotnet add package Novolis.Security.Authorization.Storage
```

## Quick start

```csharp
services.AddNovolisAuthorizationStorage();
```

## Support

Pre-release (`2026.1.*` on GitHub Packages).
