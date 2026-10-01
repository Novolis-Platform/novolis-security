<!-- novolis-pkg-brand:start -->
[![Novolis](https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.png)](https://novolis-platform.github.io/.github/novolis-security/)

[Novolis](https://github.com/Novolis-Platform) · [Docs](https://novolis-platform.github.io/.github/novolis-security/) · [Source](https://github.com/Novolis-Platform/novolis-security)
<!-- novolis-pkg-brand:end -->

# Novolis.Security.Authentication.Storage

`IRepository<T>` adapters for the identity directory and isolated credential vault. Credential rows never store `IdentityId`, email, username, phone, display name, tenant, group, or role fields.

This is not an IdP user store. Product positioning: [what this is](https://github.com/Novolis-Platform/novolis-security/blob/main/docs/what-this-is.md).

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
