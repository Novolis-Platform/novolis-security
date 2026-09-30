using System.Collections.Concurrent;

namespace Novolis.Security.OAuth;

/// <summary>Process-local <see cref="ICacheStore"/>. A farm host replaces this with a shared cache (Redis, etc.).</summary>
public sealed class InMemoryCacheStore(TimeProvider time) : ICacheStore
{
    readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public ValueTask<long> IncrementAsync(string key, TimeSpan ttl, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        var now = time.GetUtcNow();
        var expires = now + ttl;
        var next = _entries.AddOrUpdate(
            key,
            _ => new Entry(1, expires),
            (_, existing) => existing.ExpiresUtc <= now
                ? new Entry(1, expires)
                : existing with { Value = existing.Value + 1 });
        return ValueTask.FromResult(next.Value);
    }

    /// <inheritdoc />
    public ValueTask<long> GetAsync(string key, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        if (_entries.TryGetValue(key, out var existing) && existing.ExpiresUtc > time.GetUtcNow())
            return ValueTask.FromResult(existing.Value);
        return ValueTask.FromResult(0L);
    }

    /// <inheritdoc />
    public ValueTask<bool> TryCreateAsync(string key, TimeSpan ttl, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        var now = time.GetUtcNow();
        while (true)
        {
            if (_entries.TryGetValue(key, out var existing) && existing.ExpiresUtc > now)
                return ValueTask.FromResult(false);

            var fresh = new Entry(1, now + ttl);
            if (!_entries.TryGetValue(key, out existing))
                return ValueTask.FromResult(_entries.TryAdd(key, fresh));

            if (existing.ExpiresUtc > now)
                return ValueTask.FromResult(false);

            if (_entries.TryUpdate(key, fresh, existing))
                return ValueTask.FromResult(true);
        }
    }

    readonly record struct Entry(long Value, DateTimeOffset ExpiresUtc);
}
