using System.Collections.Concurrent;

namespace Novolis.Security.OAuth;

/// <summary>Thread-safe in-memory <see cref="IRefreshTokenStore"/>.</summary>
public sealed class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    readonly ConcurrentDictionary<Guid, RefreshTokenRecord> _tokens = new();

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
    public ValueTask<bool> TryRotateAsync(Guid currentId, RefreshTokenRecord replacement, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(replacement);
        if (!_tokens.TryGetValue(currentId, out var existing) || existing.RevokedUtc is not null)
            return ValueTask.FromResult(false);

        var rotated = false;
        _tokens.AddOrUpdate(
            currentId,
            existing,
            (_, current) =>
            {
                if (current.RevokedUtc is not null)
                    return current;
                current.RevokedUtc = DateTimeOffset.UtcNow;
                rotated = true;
                return current;
            });
        if (!rotated)
            return ValueTask.FromResult(false);

        _tokens[replacement.Id] = replacement;
        return ValueTask.FromResult(true);
    }
}
