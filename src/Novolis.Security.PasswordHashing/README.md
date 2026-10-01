<!-- novolis-pkg-brand:start -->
[![Novolis](https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.png)](https://novolis-platform.github.io/.github/novolis-security/)

[Novolis](https://github.com/Novolis-Platform) · [Docs](https://novolis-platform.github.io/.github/novolis-security/) · [Source](https://github.com/Novolis-Platform/novolis-security)
<!-- novolis-pkg-brand:end -->

# Novolis.Security.PasswordHashing

PBKDF2 is gone. This package hashes passwords with **Argon2id** and stores a PHC string (`$argon2id$v=19$...`). Defaults follow OWASP (19 MiB, t=2, p=1). There is no legacy verify path.

## Install

```bash
dotnet add package Novolis.Security.PasswordHashing
```

**Prerequisites:** [.NET 10 SDK](https://dotnet.microsoft.com/download) (`net10.0`).

## Quick start

```csharp
using Microsoft.Extensions.Options;
using Novolis.Security.PasswordHashing;

var hasher = new PasswordHasher(Options.Create(new PasswordHasherOptions()));
string hash = hasher.HashPassword("correct horse battery staple");
bool valid = hasher.CompareHashedPassword(hash, "correct horse battery staple");
```

Register `IPasswordHasher` via DI in ASP.NET Core hosts for credential stores.

## Related packages

| Package | When to use |
|---------|-------------|
| `Novolis.Security.Cryptography` | CSPRNG + fixed-time compare used by this hasher |
| `Novolis.Security.Secrets` | Generate initial passwords |
| `Novolis.Security.HaveIBeenPwned` | Breach checks before accepting passwords |

## More documentation

- [Getting started](https://github.com/Novolis-Platform/novolis-security/blob/main/docs/getting-started.md)
- [Design](https://github.com/Novolis-Platform/novolis-security/blob/main/docs/design.md)

## Support

Pre-release (`2026.1.*` on GitHub Packages).

