using Novolis.Security.Authentication;

namespace Novolis.Security.OAuth;

/// <summary>Short-lived, single-use Authorization Code record.</summary>
public sealed class AuthorizationCodeRecord : Novolis.Storage.Abstractions.IHasId
{
    /// <summary>Internal code identifier carried in the opaque code.</summary>
    public Guid Id { get; set; }

    /// <summary>Hash of the opaque code secret.</summary>
    public string SecretHash { get; set; } = "";

    /// <summary>Public client identifier bound to the code.</summary>
    public string ClientId { get; set; } = "";

    /// <summary>Global identity authenticated for the authorization request.</summary>
    public IdentityId IdentityId { get; set; }

    /// <summary>Exact redirect URI bound to the code.</summary>
    public string RedirectUri { get; set; } = "";

    /// <summary>PKCE challenge.</summary>
    public string CodeChallenge { get; set; } = "";

    /// <summary>PKCE challenge method. The implementation accepts only S256.</summary>
    public string CodeChallengeMethod { get; set; } = "S256";

    /// <summary>Approved OAuth scopes.</summary>
    public string Scope { get; set; } = "";

    /// <summary>Approved resource-server audience.</summary>
    public string Audience { get; set; } = "";

    /// <summary>Issue time.</summary>
    public DateTimeOffset IssuedUtc { get; set; }

    /// <summary>Expiry time.</summary>
    public DateTimeOffset ExpiresUtc { get; set; }

    /// <summary>Set atomically when the code is redeemed.</summary>
    public DateTimeOffset? ConsumedUtc { get; set; }

    /// <summary>Access-token jti issued when this code was redeemed.</summary>
    public string? AccessTokenJti { get; set; }

    /// <summary>Refresh family issued when this code was redeemed.</summary>
    public Guid? RefreshFamilyId { get; set; }
}
