<!-- novolis-pkg-brand:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.svg" width="72" alt="Novolis"/>
  </a>
</p>
<!-- novolis-pkg-brand:end -->

# Novolis.Security.Authorization.AspNetCore

Metadata-only generic attributes and minimal API extensions for the Novolis **tenant authorization framework**.

This is not OAuth and not an Identity Provider. Product positioning: [what this is](https://github.com/Novolis-Platform/novolis-security/blob/main/docs/what-this-is.md).

## Install

```bash
dotnet add package Novolis.Security.Authorization.AspNetCore
```

## Quick start

```csharp
[RequirePermission<Permissions.Moderator.Player.Kick>]
public Task KickPlayer() => Task.CompletedTask;

app.MapPost("/players/{id}/kick", KickPlayer)
    .RequirePermission<Permissions.Moderator.Player.Kick, RouteHandlerBuilder>();
```

The authorization engine remains independent of `HttpContext`.

## Support

Pre-release (`2026.1.*` on GitHub Packages).
