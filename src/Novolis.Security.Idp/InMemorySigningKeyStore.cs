using System.Collections.Concurrent;

namespace Novolis.Security.Idp;

/// <summary>Thread-safe in-memory <see cref="ISigningKeyStore"/>.</summary>
public sealed class InMemorySigningKeyStore : ISigningKeyStore
{
    readonly ConcurrentDictionary<string, IdpSigningKey> _keys = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<IdpSigningKey>> GetActiveAsync(CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        IReadOnlyList<IdpSigningKey> matches = _keys.Values
            .Where(k => k.Active && (k.NotAfterUtc is null || k.NotAfterUtc > now))
            .ToArray();
        return ValueTask.FromResult(matches);
    }

    /// <inheritdoc />
    public ValueTask<IdpSigningKey?> GetByKidAsync(string kid, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(kid);
        _keys.TryGetValue(kid, out var key);
        return ValueTask.FromResult(key);
    }

    /// <inheritdoc />
    public ValueTask UpsertAsync(IdpSigningKey key, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        _keys[key.Kid] = key;
        return ValueTask.CompletedTask;
    }
}
