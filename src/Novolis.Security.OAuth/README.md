<!-- novolis-pkg-brand:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.svg" width="72" alt="Novolis"/>
  </a>
</p>
<!-- novolis-pkg-brand:end -->

# Novolis.Security.OAuth

Standards-oriented **OAuth access-token mint**: Authorization Code + PKCE, client credentials, rotating refresh tokens, ES384 JWTs with `cnf`, and RFC 8414 discovery.

This is **not an OpenID Provider** and **not** Duende IdentityServer (or Keycloak, Auth0, Entra). It does not issue ID Tokens as a login protocol, does not expose userinfo, and does not federate to other IdPs. Product positioning: [what this is](https://github.com/Novolis-Platform/novolis-security/blob/main/docs/what-this-is.md).

This package does not own identities, credentials, roles, or permissions. Use `Novolis.Security.Authentication` for sign-in and `Novolis.Security.Authorization` for tenant-scoped capabilities.

## Install

```bash
dotnet add package Novolis.Security.OAuth
```

## Quick start

```csharp
services.AddNovolisOAuth(o =>
{
    o.Issuer = new Uri("https://accounts.example.com");
    o.IsDevelopment = true;
    o.AllowEphemeralSigningKey = true;
});
```

Password grant is not supported.

## Support

Pre-release (`2026.1.*` on GitHub Packages).
