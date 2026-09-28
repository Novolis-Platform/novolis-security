using System.Collections.Concurrent;

namespace Novolis.Security.Idp;

/// <summary>Thread-safe in-memory <see cref="IRefreshTokenStore"/>.</summary>
public sealed class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    readonly ConcurrentDictionary<Guid, IdpRefreshToken> _tokens = new();

    /// <inheritdoc />
    public ValueTask<IdpRefreshToken?> TryGetAsync(Guid id, CancellationToken ct = default)
    {
        _tokens.TryGetValue(id, out var token);
        return ValueTask.FromResult(token);
    }

    /// <inheritdoc />
    public ValueTask UpsertAsync(IdpRefreshToken token, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        _tokens[token.Id] = token;
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<IdpRefreshToken>> FindByFamilyIdAsync(Guid familyId, CancellationToken ct = default)
    {
        IReadOnlyList<IdpRefreshToken> matches = _tokens.Values.Where(t => t.FamilyId == familyId).ToArray();
        return ValueTask.FromResult(matches);
    }

    /// <inheritdoc />
    public ValueTask<bool> TryRotateAsync(Guid currentId, IdpRefreshToken replacement, CancellationToken ct = default)
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
