<!-- novolis-pkg-brand:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.svg" width="72" alt="Novolis"/>
  </a>
</p>
<!-- novolis-pkg-brand:end -->

# Novolis.Security.Authentication.Abstractions

Contracts for application sign-in: global `IdentityId`, opaque `CredentialReference`, identity-directory, credential-vault, browser-session, cache, and MFA plug-in.

The credential vault is not a user directory and not an IdP. `CredentialReference` is never a JWT subject. Product positioning: [what this is](https://github.com/Novolis-Platform/novolis-security/blob/main/docs/what-this-is.md).

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
