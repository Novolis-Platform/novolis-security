<!-- novolis-pkg-brand:start -->
[![Novolis](https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.png)](https://novolis-platform.github.io/.github/novolis-security/)

[Novolis](https://github.com/Novolis-Platform) · [Docs](https://novolis-platform.github.io/.github/novolis-security/) · [Source](https://github.com/Novolis-Platform/novolis-security)
<!-- novolis-pkg-brand:end -->

# Novolis.Security.Encryption

AES-256-GCM authenticated string encryption. The API takes a 32-byte key (`StringEncryptor.CreateKey()`). CBC/PKCS7 and GUID keys are not supported.

## Install

```bash
dotnet add package Novolis.Security.Encryption
```

**Prerequisites:** [.NET 10 SDK](https://dotnet.microsoft.com/download) (`net10.0`).

## Quick start

```csharp
using Microsoft.Extensions.Options;
using Novolis.Security.Encryption;

var encryptor = new StringEncryptor(Options.Create(new StringEncryptorOptions()));
var key = StringEncryptor.CreateKey();

string cipher = encryptor.Encrypt("payload", key);
string plain = encryptor.Decrypt(cipher, key);
```

Bind `StringEncryptorOptions` from configuration (`IOptions`) in production hosts.

## Related packages

| Package | When to use |
|---------|-------------|
| `Novolis.Security.Cryptography` | CSPRNG used for nonces and keys |
| `Novolis.Security.Secrets` | Generate keys and tokens |
| `Novolis.Security.PasswordHashing` | One-way password storage (not reversible encryption) |

## More documentation

- [Getting started](https://github.com/Novolis-Platform/novolis-security/blob/main/docs/getting-started.md)
- [Design](https://github.com/Novolis-Platform/novolis-security/blob/main/docs/design.md)

## Support

Pre-release (`2026.1.*` on GitHub Packages).

