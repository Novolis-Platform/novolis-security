<!-- novolis-marketing:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-brand-transparent.svg" width="360" alt="Novolis"/>
  </a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/banners/novolis-security.svg" width="100%" alt="novolis-security"/>
</p>

<p align="center">
  <strong>Passwords, encryption, breach checks</strong><br/>
  Password hashing, encryption, and HaveIBeenPwned helpers.
</p>

<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security/actions"><img src="https://img.shields.io/github/actions/workflow/status/Novolis-Platform/novolis-security/merge.yml?branch=main&label=merge&logo=github" alt="merge"/></a>
  <a href="https://github.com/orgs/Novolis-Platform/packages?repo_name=novolis-security"><img src="https://img.shields.io/badge/packages-GitHub%20Packages-0a7ea3?logo=nuget" alt="packages"/></a>
  <a href="https://github.com/Novolis-Platform"><img src="https://img.shields.io/badge/org-Novolis--Platform-111827" alt="org"/></a>
</p>

<p align="center">
  <a href="https://nuget.pkg.github.com/Novolis-Platform/index.json"><code>https://nuget.pkg.github.com/Novolis-Platform/index.json</code></a>
  ·
  <a href="https://github.com/Novolis-Platform/.github/blob/main/profile/README.md">Org landing</a>
  ·
  <a href="https://github.com/Novolis-Platform/novolis-governance">Governance</a>
</p>

---
<!-- novolis-marketing:end -->
<!-- novolis-package-index:start -->
> **GitHub Packages shows this repository README on every package page** (upstream limitation).
> Open the **package README** for install and quick start — embedded in each .nupkg and linked below.

## Published packages

| Package | Install | Package README |
|---------|---------|----------------|
| `Novolis.Security.Encryption` | `dotnet add package Novolis.Security.Encryption` | [README](https://github.com/Novolis-Platform/novolis-security/blob/main/src/Novolis.Security.Encryption/README.md) |
| `Novolis.Security.HaveIBeenPwned` | `dotnet add package Novolis.Security.HaveIBeenPwned` | [README](https://github.com/Novolis-Platform/novolis-security/blob/main/src/Novolis.Security.HaveIBeenPwned/README.md) |
| `Novolis.Security.PasswordHashing` | `dotnet add package Novolis.Security.PasswordHashing` | [README](https://github.com/Novolis-Platform/novolis-security/blob/main/src/Novolis.Security.PasswordHashing/README.md) |
| `Novolis.Security.Secrets` | `dotnet add package Novolis.Security.Secrets` | [README](https://github.com/Novolis-Platform/novolis-security/blob/main/src/Novolis.Security.Secrets/README.md) |

For NuGet.org and Visual Studio, the **embedded** README.md inside each package is authoritative.

<!-- novolis-package-index:end -->
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

