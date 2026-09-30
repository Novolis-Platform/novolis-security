namespace Novolis.Security.Authorization.AspNetCore;

/// <summary>Request-scoped tenant context. The engine still receives a concrete tenant id.</summary>
public sealed class TenantContextAccessor : ITenantContextAccessor
{
    /// <inheritdoc />
    public TenantId? TenantId { get; set; }
}
