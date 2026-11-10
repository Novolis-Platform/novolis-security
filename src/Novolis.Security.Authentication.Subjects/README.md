# Novolis.Security.Authentication.Subjects

Product login subjects: **email** (default) and **OpenID Connect** issuer+subject keys.

Hosts store the normalized `LoginSubject.Value` on the product user row and admit external IdP principals by matching email or `oidc:{issuer}:{subject}`. This package is not an Identity Provider.

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
