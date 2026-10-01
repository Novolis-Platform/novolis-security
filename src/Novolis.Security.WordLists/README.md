<!-- novolis-pkg-brand:start -->
[![Novolis](https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.png)](https://novolis-platform.github.io/.github/novolis-security/)

[Novolis](https://github.com/Novolis-Platform) · [Docs](https://novolis-platform.github.io/.github/novolis-security/) · [Source](https://github.com/Novolis-Platform/novolis-security)
<!-- novolis-pkg-brand:end -->

# Novolis.Security.WordLists

Curated word lists for passphrase generation. Each list is a **process-wide singleton** `IEnumerable<string>` (`IReadOnlyList<string>`) so the words stay in memory after first load.

## Quick start

```csharp
using Novolis.Security.WordLists;

foreach (var noun in Nouns.Instance)
    Console.WriteLine(noun);

var count = Adjectives.Instance.Count;
var first = Verbs.Instance[0];
```

| List | Access |
|------|--------|
| Nouns, Verbs, Adjectives, Adverbs, Countries, ColorNames, Cultures | `Type.Instance` |
| Character classes | `Characters.Uppercase`, `.Digits`, `.All`, … |

Typically consumed via `Novolis.Security.Secrets`. `Get()` factories that allocated a new `HashSet` on every call are gone.

## Support

Internal package (not published). Consumed by `Novolis.Security.Secrets`.
