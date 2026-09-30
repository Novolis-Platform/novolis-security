using System.Collections.Concurrent;

namespace Novolis.Security.Authorization;

/// <summary>Process-local tenant authorization versions.</summary>
public sealed class InMemoryAuthorizationVersionStore : IAuthorizationVersionStore
{
    readonly ConcurrentDictionary<Guid, long> _versions = new();

    /// <inheritdoc />
    public ValueTask<long> GetAsync(TenantId tenantId, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(_versions.GetOrAdd(tenantId.Value, 0));

    /// <inheritdoc />
    public ValueTask<long> IncrementAsync(TenantId tenantId, CancellationToken cancellationToken = default)
    {
        var next = _versions.AddOrUpdate(tenantId.Value, 1, (_, current) => current + 1);
        return ValueTask.FromResult(next);
    }
}
