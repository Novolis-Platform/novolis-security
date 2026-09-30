<!-- novolis-pkg-brand:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.svg" width="72" alt="Novolis"/>
  </a>
</p>
<!-- novolis-pkg-brand:end -->

# Novolis.Security.OAuth.AspNetCore

Maps the OAuth protocol surface:

- `GET /oauth/authorize`
- `POST /oauth/token`
- `POST /oauth/revoke`
- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/jwks.json`

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

This is not an OpenID Provider. An `openid-configuration` alias is opt-in and still advertises OAuth-only metadata.

## Support

Pre-release (`2026.1.*` on GitHub Packages).
