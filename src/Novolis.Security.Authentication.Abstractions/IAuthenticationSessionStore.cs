namespace Novolis.Security.Authentication;

/// <summary>Durable or process-local browser-session storage.</summary>
public interface IAuthenticationSessionStore
{
    /// <summary>Finds a session by its opaque identifier.</summary>
    ValueTask<AuthenticationSession?> TryGetAsync(
        string sessionId,
        CancellationToken cancellationToken = default);

    /// <summary>Creates a new authenticated browser session.</summary>
    ValueTask<AuthenticationSession> CreateAsync(
        IdentityId identityId,
        DateTimeOffset issuedUtc,
        DateTimeOffset expiresUtc,
        CancellationToken cancellationToken = default);

    /// <summary>Revokes a session when the account signs out or is compromised.</summary>
    ValueTask RevokeAsync(
        string sessionId,
        DateTimeOffset revokedUtc,
        CancellationToken cancellationToken = default);
}
