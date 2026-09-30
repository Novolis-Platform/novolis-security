namespace Novolis.Security.Authorization;

/// <summary>Cached assigned roles and expanded permissions for one identity in one tenant.</summary>
public sealed record EffectiveAuthorization(
    IReadOnlySet<RoleId> AssignedRoles,
    IReadOnlySet<PermissionId> Permissions);
