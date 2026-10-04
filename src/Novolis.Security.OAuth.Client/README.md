<!-- novolis-pkg-brand:start -->
[![Novolis](https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.png)](https://novolis-platform.github.io/.github/novolis-security/)

[Novolis](https://github.com/Novolis-Platform) · [Docs](https://novolis-platform.github.io/.github/novolis-security/) · [Source](https://github.com/Novolis-Platform/novolis-security)
<!-- novolis-pkg-brand:end -->

# Novolis.Security.OAuth.Client

Closed DI registration for calling APIs that use a **Novolis OAuth mint**. One call registers the named resource client, a private token client, validated options, and `INovolisOAuthClient<TApi>`.

This package does not wrap `Novolis.Http.Authentication`. Generic Basic, API key, static bearer, and any-issuer grants stay there. This package does not issue tokens; `Novolis.Security.OAuth` remains the mint.

## Install

```bash
dotnet add package Novolis.Security.OAuth.Client
```

## Quick start

```csharp
public sealed class WarehouseApi() : OAuthClientKey;

services.AddNovolisOAuthClient<WarehouseApi>(
    new Uri("https://warehouse.example/"),
    ClientCredentialsCredential.Confidential(
        issuer: new Uri("https://login.example/"),
        clientId: "warehouse",
        clientSecret: secret,
        scope: "warehouse.read"));

public sealed class WarehouseCaller(INovolisOAuthClient<WarehouseApi> api)
{
    public Task<HttpResponseMessage> ListAsync(CancellationToken ct) =>
        api.SendAsync(new HttpRequestMessage(HttpMethod.Get, "items"), ct);
}
```

A DPoP client uses `ClientCredentialsCredential.DPoP` and has no secret parameter. Refresh uses `AddNovolisOAuthClient<TApi, TStore>` after `TStore` is already registered.

The registration returns `IServiceCollection`. It does not return `IHttpClientBuilder`.

## Support

Pre-release (`2026.1.*` on GitHub Packages).
