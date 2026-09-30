namespace Novolis.Security.Authorization;

/// <summary>Tenant-scoped assignment of a role to a group.</summary>
public sealed record GroupRoleAssignment(
    TenantId TenantId,
    GroupId GroupId,
    RoleId RoleId);
