# Novolis.Security.Authentication.Entra

ASP.NET Core helpers for interactive Microsoft Entra ID / Microsoft account sign-in.

The host registers OpenID Connect, maps `/auth/microsoft/login` (configurable), and implements
`INovolisEntraPrincipalAdmission` to decide which Entra principals become product sessions.
This package is not an identity provider.
