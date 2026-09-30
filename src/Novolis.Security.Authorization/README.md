<!-- novolis-pkg-brand:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.svg" width="72" alt="Novolis"/>
  </a>
</p>
<!-- novolis-pkg-brand:end -->

# Novolis.Security.Authorization

Tenant-scoped authorization engine. Groups contain identities. Roles contain permissions. Composite roles contain roles and form an acyclic graph.

## Install

```bash
dotnet add package Novolis.Security.Authorization
```

## Quick start

```csharp
var decision = await authorization.AuthorizeAsync(
    identityId,
    tenantId,
    AuthorizationIds.Permission<Permissions.Moderator.Player.Kick>());
```

Default is deny. Authorization never guesses the tenant from an identity.

## Support

Pre-release (`2026.1.*` on GitHub Packages).
