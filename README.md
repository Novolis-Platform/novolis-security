# Security

Cryptography, secret generation, password hashing, and breach-checking libraries for the Novolis platform.

## Packages

| Package | Purpose |
|---------|---------|
| `Novolis.Security.Secrets` | Charset secrets and word passphrases (`ISecretGenerator`) |
| `Novolis.Security.PasswordHashing` | PBKDF2 password storage hashing |
| `Novolis.Security.Encryption` | Reversible AES string encryption |
| `Novolis.Security.HaveIBeenPwned` | Pwned Passwords range API client |

`Novolis.Security.WordLists` is an internal dependency (embedded word/character lists).

## Install

```bash
dotnet add package Novolis.Security.Secrets --version 0.1.0-preview.1
dotnet add package Novolis.Security.PasswordHashing --version 0.1.0-preview.1
dotnet add package Novolis.Security.Encryption --version 0.1.0-preview.1
dotnet add package Novolis.Security.HaveIBeenPwned --version 0.1.0-preview.1
```

## Quick start

```csharp
using Novolis.Security.Secrets;

var secrets = new SecretGenerator();
var apiKey = secrets.GenerateCharsetSecret();
var passphrase = secrets.GenerateWordPassphrase();
```

## Documentation

- [Getting started](docs/getting-started.md)
- [Design](docs/design.md)
- [Release](docs/release.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).
