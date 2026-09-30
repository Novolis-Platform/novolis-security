<!-- novolis-pkg-brand:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.svg" width="72" alt="Novolis"/>
  </a>
</p>
<!-- novolis-pkg-brand:end -->

# Novolis.Security.Authentication.Abstractions

Global `IdentityId`, opaque `CredentialReference`, identity-directory, credential-vault, and browser-session contracts.

The credential vault is not a user directory. `CredentialReference` is never a JWT subject.

## Install

```bash
dotnet add package Novolis.Security.Authentication.Abstractions
```

## Quick start

```csharp
IdentityId identityId = IdentityId.New();
CredentialReference credential = CredentialReference.New();
```

## Support

Pre-release (`2026.1.*` on GitHub Packages).
