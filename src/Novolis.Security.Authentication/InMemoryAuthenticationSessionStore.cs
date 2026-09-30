using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Novolis.Security.Authentication;

/// <summary>Process-local browser authentication-session store.</summary>
public sealed class InMemoryAuthenticationSessionStore : IAuthenticationSessionStore
{
    readonly ConcurrentDictionary<string, AuthenticationSession> _sessions = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public ValueTask<AuthenticationSession?> TryGetAsync(
        string sessionId,
        CancellationToken cancellationToken = default)
    {
        _sessions.TryGetValue(sessionId, out var session);
        return ValueTask.FromResult(session);
    }

    /// <inheritdoc />
    public ValueTask<AuthenticationSession> CreateAsync(
        IdentityId identityId,
        DateTimeOffset issuedUtc,
        DateTimeOffset expiresUtc,
        CancellationToken cancellationToken = default)
    {
        var buffer = RandomNumberGenerator.GetBytes(32);
        var sessionId = Convert.ToBase64String(buffer).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        CryptographicOperations.ZeroMemory(buffer);

        var session = new AuthenticationSession
        {
            SessionId = sessionId,
            IdentityId = identityId,
            IssuedUtc = issuedUtc,
            ExpiresUtc = expiresUtc,
        };

        _sessions[sessionId] = session;
        return ValueTask.FromResult(session);
    }

    /// <inheritdoc />
    public ValueTask RevokeAsync(
        string sessionId,
        DateTimeOffset revokedUtc,
        CancellationToken cancellationToken = default)
    {
        if (_sessions.TryGetValue(sessionId, out var session))
            session.RevokedUtc = revokedUtc;
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    public ValueTask RevokeAllForIdentityAsync(
        IdentityId identityId,
        DateTimeOffset revokedUtc,
        string? exceptSessionId = null,
        CancellationToken cancellationToken = default)
    {
        foreach (var session in _sessions.Values)
        {
            if (session.IdentityId != identityId || session.RevokedUtc is not null)
                continue;
            if (exceptSessionId is not null
                && string.Equals(session.SessionId, exceptSessionId, StringComparison.Ordinal))
                continue;
            session.RevokedUtc = revokedUtc;
        }

        return ValueTask.CompletedTask;
    }
}
