using System.Security.Cryptography;
using Novolis.Storage.Abstractions;

namespace Novolis.Security.Authentication.Storage;

/// <summary>Repository adapter for browser authentication sessions.</summary>
public sealed class RepositoryAuthenticationSessionStore(IRepository<StoredAuthenticationSession> repository)
    : IAuthenticationSessionStore
{
    /// <inheritdoc />
    public ValueTask<AuthenticationSession?> TryGetAsync(
        string sessionId,
        CancellationToken cancellationToken = default)
    {
        var match = repository.All().FirstOrDefault(row => string.Equals(row.SessionId, sessionId, StringComparison.Ordinal));
        return ValueTask.FromResult(match is null ? null : ToSession(match));
    }

    /// <inheritdoc />
    public async ValueTask<AuthenticationSession> CreateAsync(
        IdentityId identityId,
        DateTimeOffset issuedUtc,
        DateTimeOffset expiresUtc,
        CancellationToken cancellationToken = default)
    {
        var buffer = RandomNumberGenerator.GetBytes(32);
        var sessionId = Convert.ToBase64String(buffer).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        CryptographicOperations.ZeroMemory(buffer);

        var row = new StoredAuthenticationSession
        {
            Id = Guid.NewGuid(),
            SessionId = sessionId,
            IdentityId = identityId.Value,
            IssuedUtc = issuedUtc,
            ExpiresUtc = expiresUtc,
        };
        await repository.UpsertAsync(row, cancellationToken).ConfigureAwait(false);
        return ToSession(row);
    }

    /// <inheritdoc />
    public async ValueTask RevokeAsync(
        string sessionId,
        DateTimeOffset revokedUtc,
        CancellationToken cancellationToken = default)
    {
        var match = repository.All().FirstOrDefault(row => string.Equals(row.SessionId, sessionId, StringComparison.Ordinal));
        if (match is null)
            return;

        match.RevokedUtc = revokedUtc;
        await repository.UpsertAsync(match, cancellationToken).ConfigureAwait(false);
    }

    static AuthenticationSession ToSession(StoredAuthenticationSession row) => new()
    {
        SessionId = row.SessionId,
        IdentityId = IdentityId.FromGuid(row.IdentityId),
        IssuedUtc = row.IssuedUtc,
        ExpiresUtc = row.ExpiresUtc,
        RevokedUtc = row.RevokedUtc,
    };
}
