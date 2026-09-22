using System.Collections.Concurrent;

namespace Novolis.Security.Idp;

/// <summary>Thread-safe in-memory <see cref="IAccountStore"/>.</summary>
public sealed class InMemoryAccountStore : IAccountStore
{
    readonly ConcurrentDictionary<Guid, IdpAccount> _accounts = new();

    /// <inheritdoc />
    public ValueTask<IdpAccount?> TryGetAsync(AccountId id, CancellationToken ct = default)
    {
        _accounts.TryGetValue(id.Value, out var account);
        return ValueTask.FromResult(account);
    }

    /// <inheritdoc />
    public ValueTask UpsertAsync(IdpAccount account, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(account);
        _accounts[account.Id] = account;
        return ValueTask.CompletedTask;
    }
}
