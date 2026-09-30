<!-- novolis-pkg-brand:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.svg" width="72" alt="Novolis"/>
  </a>
</p>
<!-- novolis-pkg-brand:end -->

# Novolis.Security.Authorization.Abstractions

Tenant-scoped authorization contracts. Groups contain identities. Roles contain permissions. Composite roles contain roles.

Authorization depends on Authentication abstractions only for `IdentityId`.

## Install

```bash
dotnet add package Novolis.Security.Authorization.Abstractions
```

## Quick start

```csharp
public interface IPermission
{
    static abstract string Value { get; }
}
```

## Support

Pre-release (`2026.1.*` on GitHub Packages).
