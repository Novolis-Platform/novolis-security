<!-- novolis-pkg-brand:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.svg" width="72" alt="Novolis"/>
  </a>
</p>
<!-- novolis-pkg-brand:end -->

# Novolis.Security.Idp.AspNetCore

Maps identity / authentication endpoints onto ASP.NET Core: `POST /oauth/token`, `POST /oauth/revoke`, JWKS, and a minimal OpenID discovery document. This is not a full IDP host — TLS, HSTS, and edge rate limits stay in the executable.

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
app.UseAuthentication();
app.MapNovolisIdp();
```

HTTPS and edge IP rate limits are host concerns. Token-attempt limits are enforced in `ICacheStore`, not ASP.NET `RateLimiter`.

## Support

Pre-release (`2026.1.*` on GitHub Packages).
