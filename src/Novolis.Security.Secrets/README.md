# Novolis.Security.Secrets

Cryptographically strong secrets and memorable passphrases built from Novolis word lists.

## Install

```bash
dotnet add package Novolis.Security.Secrets
```

**Prerequisites:** [.NET 10 SDK](https://dotnet.microsoft.com/download) (`net10.0`).

## Quick start

```csharp
using Novolis.Security.Secrets;

var gen = new SecretGenerator();
string apiKey = gen.GenerateCharsetSecret(length: 32);
string passphrase = gen.GenerateWordPassphrase(wordCount: 4);

string custom = new PassphraseBuilder(wordCount: 5)
    .IncludeNouns()
    .IncludeAdjectives()
    .Shuffle()
    .Build();
```

Hash passphrases with `Novolis.Security.PasswordHashing` before persistence.

## Related packages

| Package | When to use |
|---------|-------------|
| `Novolis.Security.WordLists` | Raw word list data |
| `Novolis.Security.PasswordHashing` | PBKDF2 password storage |

## More documentation

- [Getting started](https://github.com/Novolis-Platform/novolis-security/blob/main/docs/getting-started.md)
- [Design](https://github.com/Novolis-Platform/novolis-security/blob/main/docs/design.md)

## Support

Pre-release (`2026.1.*` on GitHub Packages).
