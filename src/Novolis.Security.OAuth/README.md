<!-- novolis-pkg-brand:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.svg" width="72" alt="Novolis"/>
  </a>
</p>
<!-- novolis-pkg-brand:end -->

# Novolis.Security.OAuth

First-party identity / authentication library: **ECDSA P-384 (ES384)** access tokens, **Argon2id** password and client-secret hashes, rotating opaque refresh tokens. A full OAuth host is an executable that composes this package — this library is not that host.

## Credential store isolation (non-negotiable)

The account table is only `CredentialReference` + hash + metadata. Email/username lookup is **not this package**.

Co-locating a customer identifier with the password hash is a **grave violation of minimum secure data-store design**: one dump then names the person *and* gives the attacker their credential material. Resolve `CredentialReference` in a product directory, then call the password grant with that id.

## Install

```bash
dotnet add package Novolis.Security.OAuth
```

## Quick start

```csharp
services.AddNovolisOAuth(o =>
{
    o.Issuer = "https://idp.example";
    o.IsDevelopment = true;
    o.AllowEphemeralSigningKey = true;
});

var hasher = sp.GetRequiredService<PasswordHasher>();
var accounts = sp.GetRequiredService<ICredentialStore>();
await accounts.UpsertAsync(new CredentialRecord
{
    Id = accountId.Value,
    PasswordHash = hasher.HashPassword("correct horse battery staple"),
    CreatedUtc = DateTimeOffset.UtcNow,
});

var tokens = sp.GetRequiredService<ITokenService>();
var issued = await tokens.IssueAsync(new TokenIssueRequest
{
    GrantType = OAuthGrantTypes.Password,
    ClientId = "app",
    ClientSecret = "client-secret",
    CredentialReference = accountId,
    Password = "correct horse battery staple",
});
```

## Algorithms

| Use | Algorithm |
|-----|-----------|
| Access JWT | ES384 (NIST P-384) |
| Passwords / client secrets | Argon2id (PHC) |
| Refresh secret at rest | SHA-512 of 32 random bytes |

HMAC is not used for JWTs. RSA PKCS#1 is not used.

## Related packages

| Package | When to use |
|---------|-------------|
| `Novolis.Security.OAuth.AspNetCore` | `/oauth/token`, JWKS, discovery |
| `Novolis.Security.OAuth.Storage` | `IRepository<T>` adapters |
| `Novolis.Security.PasswordHashing` | Argon2id used by this issuer |

## Support

Pre-release (`2026.1.*` on GitHub Packages).
