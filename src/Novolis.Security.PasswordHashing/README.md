# Novolis.Security.PasswordHashing

PBKDF2 password hashing and verification with configurable work factors.

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
| `Novolis.Security.Secrets` | Generate initial passwords |
| `Novolis.Security.HaveIBeenPwned` | Breach checks before accepting passwords |

## More documentation

- [Getting started](https://github.com/Novolis-Platform/novolis-security/blob/main/docs/getting-started.md)
- [Design](https://github.com/Novolis-Platform/novolis-security/blob/main/docs/design.md)

## Support

Pre-release (`2026.1.*` on GitHub Packages).
