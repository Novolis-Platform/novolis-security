namespace Novolis.Security.Idp;

/// <summary>
/// Shared cache for rate limits and refresh-rotation leases.
/// A single-node host uses the in-memory implementation; a farm supplies a shared cache
/// (Redis, or similar) so two processes cannot both accept the same refresh token.
/// </summary>
public interface ICacheStore
{
    /// <summary>
    /// Increments a counter that expires after <paramref name="ttl"/>. Returns the value after increment.
    /// Missing or expired keys start at 1.
    /// </summary>
    ValueTask<long> IncrementAsync(string key, TimeSpan ttl, CancellationToken ct = default);

    /// <summary>Current counter value, or 0 when the key is missing or expired.</summary>
    ValueTask<long> GetAsync(string key, CancellationToken ct = default);

    /// <summary>
    /// Creates <paramref name="key"/> if it does not exist. Returns <see langword="false"/> when another caller already created it
    /// (rotation lease / once-only gate).
    /// </summary>
    ValueTask<bool> TryCreateAsync(string key, TimeSpan ttl, CancellationToken ct = default);
}
