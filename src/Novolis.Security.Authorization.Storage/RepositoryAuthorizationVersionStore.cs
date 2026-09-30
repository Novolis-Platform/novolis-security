using Novolis.Storage.Abstractions;

namespace Novolis.Security.Authorization.Storage;

/// <summary>Repository adapter for tenant authorization versions.</summary>
public sealed class RepositoryAuthorizationVersionStore(IRepository<StoredAuthorizationVersion> repository)
    : IAuthorizationVersionStore
{
    readonly Lock _gate = new();

    /// <inheritdoc />
    public async ValueTask<long> GetAsync(TenantId tenantId, CancellationToken cancellationToken = default)
    {
        var row = await repository.TryGetAsync(tenantId.Value, cancellationToken).ConfigureAwait(false);
        return row?.Version ?? 0;
    }

    /// <inheritdoc />
    public ValueTask<long> IncrementAsync(TenantId tenantId, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            var row = repository.TryGetAsync(tenantId.Value, cancellationToken).AsTask().GetAwaiter().GetResult()
                ?? new StoredAuthorizationVersion { Id = tenantId.Value, Version = 0 };
            row.Version++;
            repository.UpsertAsync(row, cancellationToken).AsTask().GetAwaiter().GetResult();
            return ValueTask.FromResult(row.Version);
        }
    }
}
