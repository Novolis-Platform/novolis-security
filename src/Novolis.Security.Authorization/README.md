<!-- novolis-pkg-brand:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.svg" width="72" alt="Novolis"/>
  </a>
</p>
<!-- novolis-pkg-brand:end -->

# Novolis.Security.Authorization

**Tenant authorization framework.** Groups contain identities. Roles contain permissions. Composite roles contain roles and form an acyclic graph. Tenant is always explicit. Default is deny.

This is not OAuth scopes, not an Identity Provider, and not Duende IdentityServer. Access tokens are minted by `Novolis.Security.OAuth`. Sign-in is `Novolis.Security.Authentication`. Product positioning: [what this is](https://github.com/Novolis-Platform/novolis-security/blob/main/docs/what-this-is.md).

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
