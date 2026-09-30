using System.Collections.Concurrent;

namespace Novolis.Security.OAuth;

/// <summary>Thread-safe in-memory <see cref="ISigningKeyStore"/>.</summary>
public sealed class InMemorySigningKeyStore : ISigningKeyStore
{
    readonly ConcurrentDictionary<string, SigningKeyRecord> _keys = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<SigningKeyRecord>> GetActiveAsync(CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        IReadOnlyList<SigningKeyRecord> matches = _keys.Values
            .Where(k => k.Active && (k.NotAfterUtc is null || k.NotAfterUtc > now))
            .ToArray();
        return ValueTask.FromResult(matches);
    }

    /// <inheritdoc />
    public ValueTask<SigningKeyRecord?> GetByKidAsync(string kid, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(kid);
        _keys.TryGetValue(kid, out var key);
        return ValueTask.FromResult(key);
    }

    /// <inheritdoc />
    public ValueTask UpsertAsync(SigningKeyRecord key, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        _keys[key.Kid] = key;
        return ValueTask.CompletedTask;
    }
}
