namespace Novolis.Security.Authorization;

/// <summary>Resolved role used by the authorization engine.</summary>
public sealed record RoleDefinition(
    RoleId Id,
    TenantId? TenantId,
    IReadOnlySet<PermissionId> Permissions,
    IReadOnlySet<RoleId> IncludedRoles,
    bool IsBuiltIn);
