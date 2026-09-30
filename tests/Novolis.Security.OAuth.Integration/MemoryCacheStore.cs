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

    public ValueTask<long> IncrementAsync(string key, TimeSpan ttl, CancellationToken ct = default)
    {
        lock (_gate)
        {
            var now = DateTimeOffset.UtcNow;
            var entry = Read(key, now);
            entry = new Entry(entry.Value + 1, now + ttl);
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
            if (Read(key, now).Value > 0)
                return ValueTask.FromResult(false);
            Write(key, new Entry(1, now + ttl));
            return ValueTask.FromResult(true);
        }
    }

    Entry Read(string key, DateTimeOffset now)
    {
        if (cache.TryGetValue(key, out Entry entry) && entry.ExpiresUtc > now)
            return entry;
        return default;
    }

    void Write(string key, Entry entry) =>
        cache.Set(key, entry, new MemoryCacheEntryOptions { AbsoluteExpiration = entry.ExpiresUtc });

    readonly record struct Entry(long Value, DateTimeOffset ExpiresUtc);
}
