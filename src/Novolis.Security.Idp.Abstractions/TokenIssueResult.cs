namespace Novolis.Security.Idp;

/// <summary>Token endpoint result. Failed results use RFC 6749 <see cref="Error"/> codes and never distinguish unknown users.</summary>
public sealed class TokenIssueResult
{
    /// <summary>True when an access token was issued.</summary>
    public bool Succeeded { get; init; }

    /// <summary>RFC 6749 error code when <see cref="Succeeded"/> is false.</summary>
    public string? Error { get; init; }

    /// <summary>Optional human-readable detail. Must not reveal whether a username exists.</summary>
    public string? ErrorDescription { get; init; }

    /// <summary>Signed JWT access token.</summary>
    public string? AccessToken { get; init; }

    /// <summary>Always <c>Bearer</c> on success.</summary>
    public string? TokenType { get; init; }

    /// <summary>Access-token lifetime in seconds.</summary>
    public int? ExpiresIn { get; init; }

    /// <summary>Opaque rotating refresh token, when the grant issues one.</summary>
    public string? RefreshToken { get; init; }

    /// <summary>Granted scope string.</summary>
    public string? Scope { get; init; }

    /// <summary>Creates a failed result.</summary>
    public static TokenIssueResult Fail(string error, string? description = null) =>
        new()
        {
            Succeeded = false,
            Error = error,
            ErrorDescription = description,
        };

    /// <summary>Creates a successful token response.</summary>
    public static TokenIssueResult Ok(string accessToken, int expiresIn, string? refreshToken, string scope) =>
        new()
        {
            Succeeded = true,
            AccessToken = accessToken,
            TokenType = "Bearer",
            ExpiresIn = expiresIn,
            RefreshToken = refreshToken,
            Scope = scope,
        };
}
