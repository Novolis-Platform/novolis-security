using System.Collections.Concurrent;

namespace Novolis.Security.Authentication;

/// <summary>
/// Process-local <see cref="ICacheStore"/>. Correct for tests and a single process.
/// A product that runs more than one process replaces this with a distributed cache.
/// </summary>
public sealed class InMemoryCacheStore(TimeProvider time) : ICacheStore
{
    readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public bool IsProcessLocal => true;

    /// <inheritdoc />
    public ValueTask<long> IncrementAsync(string key, TimeSpan ttl, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        var now = time.GetUtcNow();
        var expires = now + ttl;
        var next = _entries.AddOrUpdate(
            key,
            _ => new Entry(1, expires, null),
            (_, existing) => existing.ExpiresUtc <= now
                ? new Entry(1, expires, null)
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

            var fresh = new Entry(1, now + ttl, null);
            if (!_entries.TryGetValue(key, out existing))
                return ValueTask.FromResult(_entries.TryAdd(key, fresh));

            if (existing.ExpiresUtc > now)
                return ValueTask.FromResult(false);

            if (_entries.TryUpdate(key, fresh, existing))
                return ValueTask.FromResult(true);
        }
    }

    /// <inheritdoc />
    public ValueTask SetAsync(string key, long value, TimeSpan ttl, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        _entries[key] = new Entry(value, time.GetUtcNow() + ttl, null);
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    public ValueTask SetTextAsync(string key, string value, TimeSpan ttl, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        ArgumentNullException.ThrowIfNull(value);
        _entries[key] = new Entry(0, time.GetUtcNow() + ttl, value);
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    public ValueTask<string?> GetTextAsync(string key, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        if (_entries.TryGetValue(key, out var existing)
            && existing.ExpiresUtc > time.GetUtcNow()
            && existing.Text is not null)
            return ValueTask.FromResult<string?>(existing.Text);
        return ValueTask.FromResult<string?>(null);
    }

    readonly record struct Entry(long Value, DateTimeOffset ExpiresUtc, string? Text);
}
