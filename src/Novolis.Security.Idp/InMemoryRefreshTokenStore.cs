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
}
