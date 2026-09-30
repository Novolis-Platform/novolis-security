<!-- novolis-pkg-brand:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.svg" width="72" alt="Novolis"/>
  </a>
</p>
<!-- novolis-pkg-brand:end -->

# Novolis.Security.Authentication.Storage

`IRepository<T>` adapters for the identity directory and isolated credential vault. Credential rows never store `IdentityId`, email, username, phone, display name, tenant, group, or role fields.

## Install

```bash
dotnet add package Novolis.Security.Authentication.Storage
```

## Quick start

```csharp
services.AddNovolisAuthenticationStorage();
```

## Support

Pre-release (`2026.1.*` on GitHub Packages).
