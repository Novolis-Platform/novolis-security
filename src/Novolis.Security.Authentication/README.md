<!-- novolis-pkg-brand:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.svg" width="72" alt="Novolis"/>
  </a>
</p>
<!-- novolis-pkg-brand:end -->

# Novolis.Security.Authentication

High-level identity resolution, credential verification, and browser authentication sessions.

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
