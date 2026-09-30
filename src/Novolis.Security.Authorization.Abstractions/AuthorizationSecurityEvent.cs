using Novolis.Security.Authentication;

namespace Novolis.Security.Authorization;

/// <summary>One authorization observation. Identifiers only.</summary>
public sealed class AuthorizationSecurityEvent
{
    /// <summary>UTC timestamp from <see cref="TimeProvider"/>.</summary>
    public DateTimeOffset Utc { get; init; }

    /// <summary>One of <see cref="AuthorizationEventTypes"/>.</summary>
    public string Type { get; init; } = "";

    /// <summary>Tenant under evaluation.</summary>
    public TenantId TenantId { get; init; }

    /// <summary>Identity under evaluation when known.</summary>
    public IdentityId? IdentityId { get; init; }

    /// <summary>Optional role identifier.</summary>
    public string? RoleId { get; init; }

    /// <summary>Optional permission identifier.</summary>
    public string? PermissionId { get; init; }
}
