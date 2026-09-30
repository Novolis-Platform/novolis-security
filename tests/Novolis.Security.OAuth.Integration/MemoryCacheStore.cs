using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Novolis.Security.Authentication;
using Novolis.Security.OAuth;
using Novolis.Security.OAuth.Storage;
using Novolis.Security.PasswordHashing;
using Novolis.Storage.Abstractions;
using Novolis.Storage.Json;
using Novolis.Storage.Sqlite;

namespace Novolis.Security.Tests;

internal sealed class MemoryCacheStore(IMemoryCache cache) : ICacheStore
{
    readonly object _gate = new();

    public bool IsProcessLocal => true;

    public ValueTask<long> IncrementAsync(string key, TimeSpan ttl, CancellationToken ct = default)
    {
        lock (_gate)
        {
            var now = DateTimeOffset.UtcNow;
            var entry = Read(key, now);
            entry = new Entry(entry.Value + 1, now + ttl, entry.Text);
            Write(key, entry);
            return ValueTask.FromResult(entry.Value);
        }
    }

    public ValueTask<long> GetAsync(string key, CancellationToken ct = default)
    {
        lock (_gate)
            return ValueTask.FromResult(Read(key, DateTimeOffset.UtcNow).Value);
    }

    public ValueTask<bool> TryCreateAsync(string key, TimeSpan ttl, CancellationToken ct = default)
    {
        lock (_gate)
        {
            var now = DateTimeOffset.UtcNow;
            var existing = Read(key, now);
            if (existing.Value > 0 || existing.Text is not null)
                return ValueTask.FromResult(false);
            Write(key, new Entry(1, now + ttl, null));
            return ValueTask.FromResult(true);
        }
    }

    public ValueTask SetAsync(string key, long value, TimeSpan ttl, CancellationToken ct = default)
    {
        lock (_gate)
        {
            Write(key, new Entry(value, DateTimeOffset.UtcNow + ttl, null));
            return ValueTask.CompletedTask;
        }
    }

    public ValueTask SetTextAsync(string key, string value, TimeSpan ttl, CancellationToken ct = default)
    {
        lock (_gate)
        {
            Write(key, new Entry(0, DateTimeOffset.UtcNow + ttl, value));
            return ValueTask.CompletedTask;
        }
    }

    public ValueTask<string?> GetTextAsync(string key, CancellationToken ct = default)
    {
        lock (_gate)
            return ValueTask.FromResult(Read(key, DateTimeOffset.UtcNow).Text);
    }

    Entry Read(string key, DateTimeOffset now)
    {
        if (cache.TryGetValue(key, out Entry entry) && entry.ExpiresUtc > now)
            return entry;
        return default;
    }

    void Write(string key, Entry entry) =>
        cache.Set(key, entry, new MemoryCacheEntryOptions { AbsoluteExpiration = entry.ExpiresUtc });

    readonly record struct Entry(long Value, DateTimeOffset ExpiresUtc, string? Text);
}
