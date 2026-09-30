<!-- novolis-pkg-brand:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.svg" width="72" alt="Novolis"/>
  </a>
</p>
<!-- novolis-pkg-brand:end -->

# Novolis.Security.Authorization.Storage

`IRepository<T>` adapters for the **tenant authorization framework**: groups, memberships, custom roles, assignments, and authorization versions.

This is not OAuth storage and not an Identity Provider. Product positioning: [what this is](https://github.com/Novolis-Platform/novolis-security/blob/main/docs/what-this-is.md).

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
