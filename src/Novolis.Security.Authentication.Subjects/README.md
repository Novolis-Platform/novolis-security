# Novolis.Security.Authentication.Subjects

Product login subjects: **email** (default), **OpenID Connect**, and **secured** alphanumeric identifiers.

Hosts store a one-way hashed auth subject for sign-in. Instance owners type alphanumeric once, then only see `********` — never the hash, scheme flavor, or raw secret. This package is not an Identity Provider.

## Install

```bash
dotnet add package Novolis.Security.Authentication.Subjects
```

## Quick start

```csharp
LoginSubjects.TryCreate(LoginSubjectKind.Email, "ada@example.com", issuer: null, out var email, out _);
LoginSubjects.TryCreate(
    LoginSubjectKind.OpenIdConnect,
    subject,
    issuer: "https://login.microsoftonline.com/common/v2.0",
    out var oidc,
    out _);
```
