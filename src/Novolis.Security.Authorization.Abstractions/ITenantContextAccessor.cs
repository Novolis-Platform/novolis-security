namespace Novolis.Security.Authorization;

/// <summary>ASP.NET convenience accessor. The engine still receives a concrete <see cref="TenantId"/>.</summary>
public interface ITenantContextAccessor
{
    /// <summary>Explicit tenant for the current request, or null when unset.</summary>
    TenantId? TenantId { get; set; }
}
