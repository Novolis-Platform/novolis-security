namespace Novolis.Security.Authorization;

/// <summary>Immutable built-in role definitions registered by the application.</summary>
public sealed class BuiltInRoleRegistry
{
    readonly Dictionary<string, RoleDefinition> _roles = new(StringComparer.Ordinal);

    /// <summary>Registers a built-in role. Stored roles cannot override it.</summary>
    public void Add<TRole>()
        where TRole : IBuiltInRole
    {
        var id = AuthorizationIds.Role<TRole>();
        _roles[id.Value] = new RoleDefinition(
            id,
            TenantId: null,
            TRole.Permissions,
            IncludedRoles: new HashSet<RoleId>(),
            IsBuiltIn: true);
    }

    /// <summary>Finds a built-in role by id.</summary>
    public RoleDefinition? Find(RoleId roleId) =>
        _roles.TryGetValue(roleId.Value, out var role) ? role : null;
}
