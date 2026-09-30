using Novolis.Storage.Abstractions;

namespace Novolis.Security.OAuth.Storage;

/// <summary>Repository adapter for <see cref="IClientStore"/>.</summary>
public sealed class RepositoryClientStore(IRepository<StoredOAuthClient> repository) : IClientStore
{
    /// <inheritdoc />
    public ValueTask<OAuthClient?> FindByClientIdAsync(string clientId, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(clientId);
        var match = repository.All().FirstOrDefault(c => string.Equals(c.ClientId, clientId, StringComparison.Ordinal));
        return ValueTask.FromResult(match is null ? null : OAuthStorageMapper.ToClient(match));
    }

    /// <inheritdoc />
    public ValueTask UpsertAsync(OAuthClient client, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        return repository.UpsertAsync(OAuthStorageMapper.ToStored(client), ct);
    }
}
