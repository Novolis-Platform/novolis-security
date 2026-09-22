<!-- novolis-pkg-brand:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.svg" width="72" alt="Novolis"/>
  </a>
</p>
<!-- novolis-pkg-brand:end -->

# Novolis.Security.Idp.AspNetCore

Maps a limited IDP onto ASP.NET Core: `POST /oauth/token`, `POST /oauth/revoke`, JWKS, and a minimal OpenID discovery document.

The password grant's RFC 6749 `username` field is the **opaque `AccountId` GUID**, not an email. Resolving email/username happens in another system. Putting identifiers next to password hashes is a grave store-design violation — see `Novolis.Security.Idp.Abstractions`.

## Install

```bash
dotnet add package Novolis.Security.Idp.AspNetCore
```

## Quick start

```csharp
builder.Services.AddNovolisIdp(o =>
{
    o.Issuer = "https://idp.example";
    o.IsDevelopment = builder.Environment.IsDevelopment();
    o.AllowEphemeralSigningKey = builder.Environment.IsDevelopment();
});
builder.Services.AddAuthentication().AddNovolisJwtBearer();

var app = builder.Build();
app.UseRateLimiter();
app.UseAuthentication();
app.MapNovolisIdp();
```

HTTPS is a host concern. Call `UseRateLimiter()` before `MapNovolisIdp()`.

## Support

Pre-release (`2026.1.*` on GitHub Packages).
