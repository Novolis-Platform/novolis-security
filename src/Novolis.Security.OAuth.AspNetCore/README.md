<!-- novolis-pkg-brand:start -->
[![Novolis](https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.png)](https://novolis-platform.github.io/.github/novolis-security/)

[Novolis](https://github.com/Novolis-Platform) · [Docs](https://novolis-platform.github.io/.github/novolis-security/) · [Source](https://github.com/Novolis-Platform/novolis-security)
<!-- novolis-pkg-brand:end -->

# Novolis.Security.OAuth.AspNetCore

Maps the OAuth **token-mint** protocol surface:

- `GET /oauth/authorize`
- `POST /oauth/token`
- `POST /oauth/revoke`
- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/jwks.json`

This is **not an OpenID Provider** and not a commercial IdP (Duende IdentityServer, Keycloak, and similar). An `openid-configuration` alias is opt-in and still advertises **OAuth-only** metadata. See [what this is](https://github.com/Novolis-Platform/novolis-security/blob/main/docs/what-this-is.md).

## Install

```bash
dotnet add package Novolis.Security.OAuth.AspNetCore
```

## Quick start

```csharp
builder.Services.AddNovolisOAuth(o =>
{
    o.Issuer = new Uri("https://accounts.example.com");
});
builder.Services.AddAuthentication().AddNovolisBearer(
    issuer: new Uri("https://accounts.example.com"),
    audience: "space-game-api");

var app = builder.Build();
app.MapNovolisOAuth();
```

## Support

Pre-release (`2026.1.*` on GitHub Packages).
