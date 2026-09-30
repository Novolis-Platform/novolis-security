namespace Novolis.Security.Authentication;

/// <summary>Stable authentication event names.</summary>
public static class AuthenticationEventTypes
{
    /// <summary>Credential verification succeeded.</summary>
    public const string SignInSucceeded = "sign_in_succeeded";

    /// <summary>Credential verification failed.</summary>
    public const string SignInFailed = "sign_in_failed";

    /// <summary>A credential was disabled.</summary>
    public const string CredentialDisabled = "credential_disabled";

    /// <summary>A second factor was required or rejected.</summary>
    public const string MfaFailed = "mfa_failed";

    /// <summary>A credential was locked after too many failed sign-in attempts.</summary>
    public const string CredentialLocked = "credential_locked";

    /// <summary>A browser session was created.</summary>
    public const string SessionCreated = "session_created";

    /// <summary>A browser session was revoked.</summary>
    public const string SessionRevoked = "session_revoked";

    /// <summary>Every session and OAuth grant for the identity was revoked.</summary>
    public const string GrantsRevoked = "grants_revoked";

    /// <summary>An identity was disabled.</summary>
    public const string IdentityDisabled = "identity_disabled";

    /// <summary>The credential hash was replaced after a verified current password.</summary>
    public const string PasswordChanged = "password_changed";
}
