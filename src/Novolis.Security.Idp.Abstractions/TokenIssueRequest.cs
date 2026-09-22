namespace Novolis.Security.Idp;

/// <summary>Token endpoint request (resource-owner, client-credentials, or refresh).</summary>
public sealed class TokenIssueRequest
{
    /// <summary>One of <see cref="IdpGrantTypes"/>.</summary>
    public string GrantType { get; init; } = "";

    /// <summary>OAuth <c>client_id</c>.</summary>
    public string? ClientId { get; init; }

    /// <summary>OAuth <c>client_secret</c>.</summary>
    public string? ClientSecret { get; init; }

    /// <summary>
    /// Already-resolved account for the password grant.
    /// Resolve email/username in a separate directory first; passing those strings into the IDP is forbidden.
    /// </summary>
    public AccountId? AccountId { get; init; }

    /// <summary>Resource-owner password.</summary>
    public string? Password { get; init; }

    /// <summary>Previous refresh token (<c>{id}.{secret}</c>).</summary>
    public string? RefreshToken { get; init; }

    /// <summary>Space-separated scopes. Empty means the client's full allow-list.</summary>
    public string? Scope { get; init; }
}
