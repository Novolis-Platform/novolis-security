using System.Text.Json.Serialization;

namespace Novolis.Security.OAuth.Client;

/// <summary>JSON body returned by an OAuth token endpoint.</summary>
internal sealed class NovolisOAuthTokenResponse
{
    /// <summary>Access token.</summary>
    [JsonPropertyName("access_token")]
    public string? AccessToken { get; init; }

    /// <summary>Token type. Defaults to Bearer when omitted.</summary>
    [JsonPropertyName("token_type")]
    public string? TokenType { get; init; }

    /// <summary>Lifetime in seconds.</summary>
    [JsonPropertyName("expires_in")]
    public int? ExpiresIn { get; init; }

    /// <summary>Refresh token when issued or rotated.</summary>
    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; init; }

    /// <summary>OAuth error code when the request failed.</summary>
    [JsonPropertyName("error")]
    public string? Error { get; init; }
}
