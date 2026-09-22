using Novolis.Security.Idp;
using Novolis.Storage.Abstractions;

namespace Novolis.Security.Idp.Storage;

/// <summary><see cref="IRepository{T}"/> adapter for <see cref="IAccountStore"/>. Lookup is by <see cref="AccountId"/> only.</summary>
public sealed class RepositoryAccountStore(IRepository<IdpAccount> repository) : IAccountStore
{
    /// <inheritdoc />
    public ValueTask<IdpAccount?> TryGetAsync(AccountId id, CancellationToken ct = default) =>
        repository.TryGetAsync(id.Value, ct);

    /// <inheritdoc />
    public ValueTask UpsertAsync(IdpAccount account, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(account);
        return repository.UpsertAsync(account, ct);
    }
}
