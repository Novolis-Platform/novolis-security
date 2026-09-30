using System.Collections.Concurrent;
using Novolis.Security.Authentication;

namespace Novolis.Security.OAuth;

/// <summary>Thread-safe in-memory refresh-token store with atomic rotation.</summary>
public sealed class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    readonly ConcurrentDictionary<Guid, RefreshTokenRecord> _tokens = new();
    readonly Lock _gate = new();

    /// <inheritdoc />
    public ValueTask<RefreshTokenRecord?> TryGetAsync(Guid id, CancellationToken ct = default)
    {
        _tokens.TryGetValue(id, out var token);
        return ValueTask.FromResult(token);
    }

    /// <inheritdoc />
    public ValueTask UpsertAsync(RefreshTokenRecord token, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        _tokens[token.Id] = token;
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<RefreshTokenRecord>> FindByFamilyIdAsync(Guid familyId, CancellationToken ct = default)
    {
        IReadOnlyList<RefreshTokenRecord> matches = _tokens.Values.Where(t => t.FamilyId == familyId).ToArray();
        return ValueTask.FromResult(matches);
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<RefreshTokenRecord>> FindByIdentityIdAsync(
        IdentityId identityId,
        CancellationToken ct = default)
    {
        IReadOnlyList<RefreshTokenRecord> matches = _tokens.Values
            .Where(t => t.IdentityId == identityId)
            .ToArray();
        return ValueTask.FromResult(matches);
    }

    /// <inheritdoc />
    public ValueTask<RefreshRotationResult> TryRotateAsync(
        Guid currentId,
        RefreshTokenRecord replacement,
        DateTimeOffset now,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(replacement);
        lock (_gate)
        {
            if (!_tokens.TryGetValue(currentId, out var existing))
                return ValueTask.FromResult(RefreshRotationResult.Failure());
            if (existing.RevokedUtc is not null)
                return ValueTask.FromResult(RefreshRotationResult.Failure(replayed: true));
            if (existing.ExpiresUtc <= now)
                return ValueTask.FromResult(RefreshRotationResult.Failure());

            existing.RevokedUtc = now;
            existing.ReplacedById = replacement.Id;
            _tokens[replacement.Id] = replacement;
            return ValueTask.FromResult(RefreshRotationResult.Success());
        }
    }

    /// <inheritdoc />
    public ValueTask RevokeAsync(Guid tokenId, DateTimeOffset revokedUtc, CancellationToken ct = default)
    {
        if (_tokens.TryGetValue(tokenId, out var token) && token.RevokedUtc is null)
            token.RevokedUtc = revokedUtc;
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    public ValueTask RevokeFamilyAsync(Guid familyId, DateTimeOffset revokedUtc, CancellationToken ct = default)
    {
        lock (_gate)
        {
            foreach (var token in _tokens.Values.Where(t => t.FamilyId == familyId))
            {
                if (token.RevokedUtc is null)
                    token.RevokedUtc = revokedUtc;
            }
        }

        return ValueTask.CompletedTask;
    }
}
