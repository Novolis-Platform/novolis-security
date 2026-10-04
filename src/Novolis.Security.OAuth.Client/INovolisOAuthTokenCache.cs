namespace Novolis.Security.OAuth.Client;

/// <summary>In-memory cache of acquired access tokens.</summary>
internal interface INovolisOAuthTokenCache
{
    /// <summary>Tries to read a token for <paramref name="cacheKey"/>.</summary>
    bool TryGet(string cacheKey, out CachedOAuthAccessToken? token);

    /// <summary>Stores a token under <paramref name="cacheKey"/> for <paramref name="clientName"/>.</summary>
    void Set(string clientName, string cacheKey, CachedOAuthAccessToken token);

    /// <summary>Removes every entry owned by <paramref name="clientName"/>.</summary>
    void Invalidate(string clientName);
}
