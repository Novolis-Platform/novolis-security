namespace Novolis.Security.OAuth;

/// <summary>OAuth token endpoint request.</summary>
public sealed class TokenIssueRequest
{
    /// <summary>One of <see cref="OAuthGrantTypes"/>.</summary>
    public string GrantType { get; init; } = "";

    /// <summary>OAuth <c>client_id</c>.</summary>
    public string? ClientId { get; init; }

    /// <summary>OAuth <c>client_secret</c>.</summary>
    public string? ClientSecret { get; init; }

    /// <summary>Authorization Code.</summary>
    public string? AuthorizationCode { get; init; }

    /// <summary>Exact redirect URI used when the code was issued.</summary>
    public string? RedirectUri { get; init; }

    /// <summary>PKCE verifier.</summary>
    public string? CodeVerifier { get; init; }

    /// <summary>Previous refresh token (<c>{id}.{secret}</c>).</summary>
    public string? RefreshToken { get; init; }

    /// <summary>Space-separated scopes. Empty means the client's full allow-list.</summary>
    public string? Scope { get; init; }

    /// <summary>Requested resource-server audience.</summary>
    public string? Audience { get; init; }

    /// <summary>Caller address used for per-IP attempt limits.</summary>
    public string? RemoteAddress { get; init; }

    /// <summary>RFC 9449 DPoP proof JWT.</summary>
    public string? DPoPProof { get; init; }

    /// <summary>HTTP method bound to the DPoP proof.</summary>
    public string HttpMethod { get; init; } = "POST";

    /// <summary>HTTP URI bound to the DPoP proof, without a query string.</summary>
    public string HttpUri { get; init; } = "";

    /// <summary>SHA-256 thumbprint of a presented client certificate, Base64URL.</summary>
    public string? CertificateThumbprintSha256 { get; init; }
}
