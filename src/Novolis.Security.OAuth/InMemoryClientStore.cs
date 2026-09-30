using System.Collections.Concurrent;

namespace Novolis.Security.OAuth;

/// <summary>Thread-safe in-memory <see cref="IClientStore"/>.</summary>
public sealed class InMemoryClientStore : IClientStore
{
    readonly ConcurrentDictionary<string, OAuthClient> _clients = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public ValueTask<OAuthClient?> FindByClientIdAsync(string clientId, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(clientId);
        _clients.TryGetValue(clientId, out var client);
        return ValueTask.FromResult(client);
    }

    /// <inheritdoc />
    public ValueTask UpsertAsync(OAuthClient client, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        _clients[client.ClientId] = client;
        return ValueTask.CompletedTask;
    }
}
