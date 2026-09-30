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

    /// <summary>A browser session was created.</summary>
    public const string SessionCreated = "session_created";

    /// <summary>A browser session was revoked.</summary>
    public const string SessionRevoked = "session_revoked";
}
