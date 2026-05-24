# Novolis.Security.WordLists

Curated word lists (nouns, verbs, adjectives, countries, colors) for passphrase generation.

## Install

```bash
dotnet add package Novolis.Security.WordLists
```

**Prerequisites:** [.NET 10 SDK](https://dotnet.microsoft.com/download) (`net10.0`).

## Quick start

```csharp
using Novolis.Security.WordLists;

IEnumerable<string> nouns = Nouns.Get();
IEnumerable<string> adjectives = Adjectives.Get();
IEnumerable<char> digits = Characters.Digits;
IEnumerable<string> verbs = Verbs.Get();
```

Typically consumed via `Novolis.Security.Secrets` rather than referenced directly in apps.

## Related packages

| Package | When to use |
|---------|-------------|
| `Novolis.Security.Secrets` | `SecretGenerator` and `PassphraseBuilder` |
| `Novolis.Security.PasswordHashing` | Store generated secrets safely |

## More documentation

- [Getting started](https://github.com/Novolis-Platform/novolis-security/blob/main/docs/getting-started.md)
- [Design](https://github.com/Novolis-Platform/novolis-security/blob/main/docs/design.md)

## Support

Pre-release (`2026.1.*` on GitHub Packages).
