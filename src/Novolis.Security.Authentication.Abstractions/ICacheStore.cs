namespace Novolis.Security.Authentication;

/// <summary>
/// Product-replaceable shared cache for sign-in lockout, MFA challenges, token-attempt limits,
/// identity not-before cutoffs, and refresh/code leases.
/// </summary>
/// <remarks>
/// In-memory is correct for tests and a single process. A farm, pod replica set, or multi-app
/// host replaces this with a distributed backing store (Redis or similar) so every process
/// sees the same counters and once-only gates.
/// </remarks>
public interface ICacheStore
{
    /// <summary>
    /// Whether this implementation is process-local. Distributed product caches return
    /// <see langword="false"/>.
    /// </summary>
    bool IsProcessLocal { get; }

    /// <summary>
    /// Increments a counter that expires after <paramref name="ttl"/>. Returns the value after increment.
    /// Missing or expired keys start at 1.
    /// </summary>
    ValueTask<long> IncrementAsync(string key, TimeSpan ttl, CancellationToken ct = default);

    /// <summary>Current counter value, or 0 when the key is missing or expired.</summary>
    ValueTask<long> GetAsync(string key, CancellationToken ct = default);

    /// <summary>
    /// Creates <paramref name="key"/> if it does not exist. Returns <see langword="false"/> when another caller already created it
    /// (rotation lease / once-only MFA proof / once-only gate).
    /// </summary>
    ValueTask<bool> TryCreateAsync(string key, TimeSpan ttl, CancellationToken ct = default);

    /// <summary>Sets an absolute numeric value that expires after <paramref name="ttl"/>.</summary>
    ValueTask SetAsync(string key, long value, TimeSpan ttl, CancellationToken ct = default);

    /// <summary>Stores opaque text (MFA challenges) that expires after <paramref name="ttl"/>.</summary>
    ValueTask SetTextAsync(string key, string value, TimeSpan ttl, CancellationToken ct = default);

    /// <summary>Current text value, or <see langword="null"/> when the key is missing or expired.</summary>
    ValueTask<string?> GetTextAsync(string key, CancellationToken ct = default);
}
