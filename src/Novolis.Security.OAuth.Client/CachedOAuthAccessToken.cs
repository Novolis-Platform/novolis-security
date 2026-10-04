namespace Novolis.Security.OAuth.Client;

/// <summary>Access token stored for a named resource client.</summary>
internal sealed class CachedOAuthAccessToken
{
    /// <summary>Access token value.</summary>
    public required string AccessToken { get; init; }

    /// <summary>Authorization scheme. Bearer for confidential clients, DPoP when proofs are required.</summary>
    public string TokenType { get; init; } = "Bearer";

    /// <summary>Instant after which the token is treated as expired.</summary>
    public DateTimeOffset ExpiresAt { get; init; }
}
