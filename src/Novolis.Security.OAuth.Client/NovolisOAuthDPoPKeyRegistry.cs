using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Novolis.Security.OAuth.Client;

/// <summary>Holds host-owned DPoP signing keys by resource client name.</summary>
internal sealed class NovolisOAuthDPoPKeyRegistry
{
    private readonly ConcurrentDictionary<string, ECDsa> _keys = new(StringComparer.Ordinal);

    /// <summary>Stores <paramref name="key"/> for <paramref name="clientName"/>.</summary>
    public void Set(string clientName, ECDsa key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientName);
        ArgumentNullException.ThrowIfNull(key);
        _keys[clientName] = key;
    }

    /// <summary>Tries to read the DPoP key for <paramref name="clientName"/>.</summary>
    public bool TryGet(string clientName, out ECDsa? key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientName);
        return _keys.TryGetValue(clientName, out key);
    }
}
