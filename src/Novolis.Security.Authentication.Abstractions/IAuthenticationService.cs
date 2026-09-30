namespace Novolis.Security.Authentication;

/// <summary>High-level application authentication façade.</summary>
public interface IAuthenticationService
{
    /// <summary>
    /// Resolves an identifier through the identity directory and verifies its credential.
    /// This is not an OAuth Resource Owner Password Credentials grant.
    /// </summary>
    ValueTask<SignInResult> SignInAsync(
        string identifier,
        string password,
        bool createSession = true,
        CancellationToken cancellationToken = default);

    /// <summary>Validates a browser session without guessing a tenant.</summary>
    ValueTask<IdentityId?> GetAuthenticatedIdentityAsync(
        string sessionId,
        CancellationToken cancellationToken = default);

    /// <summary>Creates an identity and isolated credential material for a new account.</summary>
    ValueTask<SignInResult> RegisterAsync(
        string identifier,
        string password,
        string? displayName = null,
        bool createSession = true,
        CancellationToken cancellationToken = default);

    /// <summary>Revokes a browser authentication session.</summary>
    ValueTask SignOutAsync(
        string sessionId,
        CancellationToken cancellationToken = default);
}
