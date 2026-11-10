# Novolis.Security.Authentication.Enrollment

Opaque enrollment / invite tokens and product invite links.

Hosts mint a one-time link, show it in the product UI (preferred when mail is unavailable), and may also enqueue email. This package does not send mail and is not an Identity Provider.

## Install

```bash
dotnet add package Novolis.Security.Authentication.Enrollment
```

## Quick start

```csharp
var mint = new EnrollmentTokenMint(new EnrollmentTokenOptions
{
    Pepper = configuration["Enrollment:Pepper"],
    AllowDevelopmentPepper = environment.IsDevelopment(),
    LinkPath = "invite",
});

var reference = mint.CreateReference();
var inviteUrl = mint.CreateLink("https://app.example", reference);
var tokenHash = mint.HashToken(mint.CreateToken(reference));
```
