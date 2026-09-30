namespace Novolis.Security.OAuth;

/// <summary>Result returned after a validated Authorization Code request.</summary>
public sealed class AuthorizationCodeIssueResult
{
    /// <summary>Whether an authorization code was issued.</summary>
    public bool Succeeded { get; init; }

    /// <summary>Opaque code returned to the client.</summary>
    public string? Code { get; init; }

    /// <summary>OAuth error code when issuance fails.</summary>
    public string? Error { get; init; }

    /// <summary>Granted scope.</summary>
    public string? Scope { get; init; }

    /// <summary>Granted audience.</summary>
    public string? Audience { get; init; }

    /// <summary>Creates a failed result.</summary>
    public static AuthorizationCodeIssueResult Fail(string error) =>
        new() { Error = error };

    /// <summary>Creates a successful result.</summary>
    public static AuthorizationCodeIssueResult Success(
        string code,
        string scope,
        string audience) =>
        new()
        {
            Succeeded = true,
            Code = code,
            Scope = scope,
            Audience = audience,
        };
}
