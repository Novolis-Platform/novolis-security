using System.Collections.Concurrent;

namespace Novolis.Security.Idp;

/// <summary>Thread-safe in-memory <see cref="IClientStore"/>.</summary>
public sealed class InMemoryClientStore : IClientStore
{
    readonly ConcurrentDictionary<string, IdpClient> _clients = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public ValueTask<IdpClient?> FindByClientIdAsync(string clientId, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(clientId);
        _clients.TryGetValue(clientId, out var client);
        return ValueTask.FromResult(client);
    }

    /// <inheritdoc />
    public ValueTask UpsertAsync(IdpClient client, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        _clients[client.ClientId] = client;
        return ValueTask.CompletedTask;
    }
}
