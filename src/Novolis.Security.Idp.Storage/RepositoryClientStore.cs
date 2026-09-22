using Novolis.Security.Idp;
using Novolis.Storage.Abstractions;

namespace Novolis.Security.Idp.Storage;

/// <summary><see cref="IRepository{T}"/> adapter for <see cref="IClientStore"/>.</summary>
public sealed class RepositoryClientStore(IRepository<IdpClient> repository) : IClientStore
{
    /// <inheritdoc />
    public ValueTask<IdpClient?> FindByClientIdAsync(string clientId, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(clientId);
        var match = repository.All().FirstOrDefault(c => string.Equals(c.ClientId, clientId, StringComparison.Ordinal));
        return ValueTask.FromResult(match);
    }

    /// <inheritdoc />
    public ValueTask UpsertAsync(IdpClient client, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        return repository.UpsertAsync(client, ct);
    }
}
