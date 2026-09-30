namespace Novolis.Security.Authorization;

/// <summary>Monotonic tenant authorization version used for cache keys.</summary>
public interface IAuthorizationVersionStore
{
    /// <summary>Current version for the tenant.</summary>
    ValueTask<long> GetAsync(TenantId tenantId, CancellationToken cancellationToken = default);

    /// <summary>Increments the version after a graph mutation.</summary>
    ValueTask<long> IncrementAsync(TenantId tenantId, CancellationToken cancellationToken = default);
}
