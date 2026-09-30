namespace Novolis.Security.Authentication;

/// <summary>Result of application-level credential authentication.</summary>
public sealed class SignInResult
{
    /// <summary>Whether authentication succeeded.</summary>
    public bool Succeeded { get; init; }

    /// <summary>Authenticated global identity on success.</summary>
    public IdentityId? IdentityId { get; init; }

    /// <summary>Opaque browser session id on success when a session was created.</summary>
    public string? SessionId { get; init; }

    /// <summary>Non-sensitive failure category.</summary>
    public string? Error { get; init; }

    /// <summary>Creates a failed result.</summary>
    public static SignInResult Fail(string error = "invalid_credentials") =>
        new() { Error = error };

    /// <summary>Creates a successful result.</summary>
    public static SignInResult Success(IdentityId identityId, string? sessionId = null) =>
        new()
        {
            Succeeded = true,
            IdentityId = identityId,
            SessionId = sessionId,
        };
}
