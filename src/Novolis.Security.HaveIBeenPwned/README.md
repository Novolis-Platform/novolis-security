# Novolis.Security.HaveIBeenPwned

Have I Been Pwned k-anonymity range API client for password breach checks.

## Install

```bash
dotnet add package Novolis.Security.HaveIBeenPwned
```

**Prerequisites:** [.NET 10 SDK](https://dotnet.microsoft.com/download) (`net10.0`), outbound HTTPS.

## Quick start

```csharp
using Novolis.Security.HaveIBeenPwned;

// Register IHaveIBeenPwnedClient with IHttpClientFactory + IOptions<HibpConfiguration> in DI.
bool pwned = await client.IsPwnedAsync("password123", threshold: 1);

IEnumerable<PasswordDetails> details =
    await client.GetPasswordDetailsAsync("password123");
```

Passwords are never sent in full — only a SHA-1 prefix is transmitted per HIBP rules.

## Related packages

| Package | When to use |
|---------|-------------|
| `Novolis.Security.PasswordHashing` | Store passwords after policy checks |
| `Novolis.Security.Secrets` | Generate replacement credentials |

## More documentation

- [Getting started](https://github.com/Novolis-Platform/novolis-security/blob/main/docs/getting-started.md)
- [Design](https://github.com/Novolis-Platform/novolis-security/blob/main/docs/design.md)

## Support

Pre-release (`2026.1.*` on GitHub Packages). Requires network access to `api.pwnedpasswords.com`.
