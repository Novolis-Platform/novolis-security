using System.Collections.Concurrent;
using Microsoft.Extensions.Caching.Memory;

namespace Novolis.Security.OAuth.Client;

/// <summary>Stores access tokens in <see cref="IMemoryCache"/> and tracks keys per client name.</summary>
internal sealed class NovolisOAuthTokenCache(IMemoryCache cache, TimeProvider time) : INovolisOAuthTokenCache
{
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, byte>> _keysByClient = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public bool TryGet(string cacheKey, out CachedOAuthAccessToken? token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cacheKey);
        if (cache.TryGetValue(cacheKey, out CachedOAuthAccessToken? stored) && stored is not null)
        {
            if (stored.ExpiresAt > time.GetUtcNow())
            {
                token = stored;
                return true;
            }
        }

        token = null;
        return false;
    }

    /// <inheritdoc />
    public void Set(string clientName, string cacheKey, CachedOAuthAccessToken token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientName);
        ArgumentException.ThrowIfNullOrWhiteSpace(cacheKey);
        ArgumentNullException.ThrowIfNull(token);
        cache.Set(cacheKey, token, new MemoryCacheEntryOptions
        {
            AbsoluteExpiration = token.ExpiresAt,
        });
        _keysByClient.GetOrAdd(clientName, static _ => new ConcurrentDictionary<string, byte>(StringComparer.Ordinal))
            .TryAdd(cacheKey, 0);
    }

    /// <inheritdoc />
    public void Invalidate(string clientName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientName);
        if (!_keysByClient.TryRemove(clientName, out var keys))
        {
            return;
        }

        foreach (var key in keys.Keys)
        {
            cache.Remove(key);
        }
    }
}
