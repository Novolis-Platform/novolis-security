using System.Text.Json.Serialization;

namespace Novolis.Security.OAuth.Client;

/// <summary>RFC 8414 metadata used by the outbound client.</summary>
internal sealed class NovolisOAuthDiscoveryDocument
{
    /// <summary>Token endpoint.</summary>
    [JsonPropertyName("token_endpoint")]
    public string? TokenEndpoint { get; init; }

    /// <summary>Revocation endpoint.</summary>
    [JsonPropertyName("revocation_endpoint")]
    public string? RevocationEndpoint { get; init; }
}
