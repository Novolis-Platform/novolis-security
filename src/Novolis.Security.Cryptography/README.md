<!-- novolis-pkg-brand:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.svg" width="72" alt="Novolis"/>
  </a>
</p>
<!-- novolis-pkg-brand:end -->

# Novolis.Security.Cryptography

BCL wrappers for operations that are easy to get wrong: **CSPRNG**, **fixed-time equality**, and **HKDF-SHA512**.

Do not use `Random`, `Equals` on secret strings, or ad-hoc SHA-256 stretching for key derivation.

## Install

```bash
dotnet add package Novolis.Security.Cryptography
```

```csharp
var key = SecureRandom.GetBytes(32);
var ok = ConstantTime.Equals(left, right);
SecureMemory.Zero(key);
var derived = HkdfSha512.Derive(key, 32, info: "novolis-idp"u8);
```

## Support

Pre-release (`2026.1.*` on GitHub Packages).
