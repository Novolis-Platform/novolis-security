<!-- novolis-pkg-brand:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.svg" width="72" alt="Novolis"/>
  </a>
</p>
<!-- novolis-pkg-brand:end -->

# Novolis.Security.Authentication.AspNetCore

High-level ASP.NET Core façade for Novolis authentication. It composes identity/credential verification, browser sessions, and the standards-oriented OAuth authorization server.

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
