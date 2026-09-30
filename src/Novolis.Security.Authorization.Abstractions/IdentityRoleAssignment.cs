using Novolis.Security.Authentication;

namespace Novolis.Security.Authorization;

/// <summary>Direct tenant-scoped assignment of a role to an identity.</summary>
public sealed record IdentityRoleAssignment(
    TenantId TenantId,
    IdentityId IdentityId,
    RoleId RoleId);
