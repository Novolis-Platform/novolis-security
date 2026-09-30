<!-- novolis-pkg-brand:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.svg" width="72" alt="Novolis"/>
  </a>
</p>
<!-- novolis-pkg-brand:end -->

# Novolis.Security.OAuth.Abstractions

OAuth contracts: clients, authorization codes, refresh tokens, signing keys, and atomic store operations.

OAuth scopes are not application permissions. JWT `sub` is a global `IdentityId`, never a `CredentialReference`.

## Install

```bash
dotnet add package Novolis.Security.OAuth.Abstractions
```

## Quick start

```csharp
TokenIssueResult tokens = await tokenService.IssueAsync(request, cancellationToken);
```

## Support

Pre-release (`2026.1.*` on GitHub Packages).
