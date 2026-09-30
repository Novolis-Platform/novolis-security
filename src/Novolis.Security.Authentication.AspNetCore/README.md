<!-- novolis-pkg-brand:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.svg" width="72" alt="Novolis"/>
  </a>
</p>
<!-- novolis-pkg-brand:end -->

# Novolis.Security.Authentication.AspNetCore

ASP.NET Core façade for Novolis **application sign-in** (sessions). It may also map the OAuth **token-mint** endpoints for first-party hosts.

This is not an Identity Provider and not Duende IdentityServer. Sign-in stays an Authentication API. Token mint stays OAuth. Tenant authz is a separate family. Product positioning: [what this is](https://github.com/Novolis-Platform/novolis-security/blob/main/docs/what-this-is.md).

## Install

```bash
dotnet add package Novolis.Security.Authentication.AspNetCore
```

## Quick start

```csharp
builder.Services
    .AddNovolisAuthentication(options =>
    {
        options.Issuer = new Uri("https://accounts.example.com");
    })
    .AddNovolisAuthorization();

var app = builder.Build();
app.MapNovolisOAuth();
```

Sign-in is an Authentication API. It never uses the OAuth Resource Owner Password Credentials grant.

## Support

Pre-release (`2026.1.*` on GitHub Packages).
