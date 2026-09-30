<!-- novolis-pkg-brand:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.svg" width="72" alt="Novolis"/>
  </a>
</p>
<!-- novolis-pkg-brand:end -->

# Novolis.Security.Authentication

Application **sign-in**: identifier resolution, isolated Argon2id credentials, browser sessions, lockout, optional `IMfaProvider`.

This is not an Identity Provider, not OAuth, and not Duende IdentityServer. OAuth access tokens belong in `Novolis.Security.OAuth`. Tenant permissions belong in `Novolis.Security.Authorization`. Product positioning: [what this is](https://github.com/Novolis-Platform/novolis-security/blob/main/docs/what-this-is.md).

## Install

```bash
dotnet add package Novolis.Security.Authentication
```

## Quick start

```csharp
var result = await authentication.SignInAsync(identifier, password, cancellationToken);
```

This establishes an authenticated session. It is not an OAuth password grant.

## Support

Pre-release (`2026.1.*` on GitHub Packages).
