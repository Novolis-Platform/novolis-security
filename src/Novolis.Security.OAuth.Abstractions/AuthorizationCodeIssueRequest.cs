using Novolis.Security.Authentication;

namespace Novolis.Security.OAuth;

/// <summary>Validated authorization request used to issue an opaque code.</summary>
public sealed class AuthorizationCodeIssueRequest
{
    /// <summary>Public OAuth client identifier.</summary>
    public string ClientId { get; init; } = "";

    /// <summary>Exact registered redirect URI.</summary>
    public string RedirectUri { get; init; } = "";

    /// <summary>Authenticated global identity.</summary>
    public IdentityId IdentityId { get; init; }

    /// <summary>Approved space-separated scopes.</summary>
    public string Scope { get; init; } = "";

    /// <summary>Approved resource-server audience.</summary>
    public string Audience { get; init; } = "";

    /// <summary>PKCE S256 challenge.</summary>
    public string CodeChallenge { get; init; } = "";

    /// <summary>PKCE method; only S256 is accepted.</summary>
    public string CodeChallengeMethod { get; init; } = "S256";
}
