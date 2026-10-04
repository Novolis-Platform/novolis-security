namespace Novolis.Security.OAuth.Client;

/// <summary>Named options for one Novolis OAuth resource client.</summary>
internal sealed class NovolisOAuthClientOptions
{
    /// <summary>Resource API base address.</summary>
    public Uri BaseAddress { get; set; } = null!;

    /// <summary>Authorization-server issuer.</summary>
    public Uri Issuer { get; set; } = null!;

    /// <summary>OAuth client identifier.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Requested scope.</summary>
    public string Scope { get; set; } = string.Empty;

    /// <summary>Client secret for confidential clients.</summary>
    public string? ClientSecret { get; set; }

    /// <summary>Explicit token endpoint when discovery is skipped.</summary>
    public Uri? TokenEndpoint { get; set; }

    /// <summary>Whether resource and token calls send DPoP proofs.</summary>
    public bool UseDPoP { get; set; }

    /// <summary>Whether tokens are acquired with the refresh-token grant.</summary>
    public bool UseRefresh { get; set; }
}
