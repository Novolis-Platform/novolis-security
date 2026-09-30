namespace Novolis.Security.Authorization;

/// <summary>Stable authorization event names.</summary>
public static class AuthorizationEventTypes
{
    /// <summary>An authorization decision was denied.</summary>
    public const string AuthorizationDenied = "authorization_denied";

    /// <summary>A role was assigned.</summary>
    public const string RoleAssigned = "role_assigned";

    /// <summary>A role assignment was removed.</summary>
    public const string RoleRemoved = "role_removed";

    /// <summary>Group membership changed.</summary>
    public const string GroupMembershipChanged = "group_membership_changed";

    /// <summary>A custom role changed.</summary>
    public const string CustomRoleChanged = "custom_role_changed";

    /// <summary>A composite role changed.</summary>
    public const string CompositeRoleChanged = "composite_role_changed";
}
