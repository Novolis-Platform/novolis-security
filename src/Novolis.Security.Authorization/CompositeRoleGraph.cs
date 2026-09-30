namespace Novolis.Security.Authorization;

/// <summary>Validates and expands acyclic composite-role graphs.</summary>
public static class CompositeRoleGraph
{
    /// <summary>Throws when adding <paramref name="included"/> to <paramref name="roleId"/> would create a cycle.</summary>
    public static void ThrowIfCycle(
        RoleId roleId,
        IReadOnlySet<RoleId> included,
        IReadOnlyDictionary<string, RoleDefinition> known)
    {
        var visiting = new HashSet<string>(StringComparer.Ordinal);
        var visited = new HashSet<string>(StringComparer.Ordinal);
        if (Walk(roleId.Value, included, known, visiting, visited))
            throw new InvalidOperationException($"Composite role '{roleId.Value}' introduces a cycle.");
    }

    /// <summary>Expands assigned roles into the union of reachable permissions. Cycles fail closed.</summary>
    public static HashSet<PermissionId> ExpandPermissions(
        IEnumerable<RoleId> assigned,
        Func<RoleId, RoleDefinition?> resolve)
    {
        var permissions = new HashSet<PermissionId>();
        var visiting = new HashSet<string>(StringComparer.Ordinal);
        var visited = new HashSet<string>(StringComparer.Ordinal);
        foreach (var roleId in assigned)
            WalkPermissions(roleId, resolve, permissions, visiting, visited);
        return permissions;
    }

    static bool Walk(
        string current,
        IReadOnlySet<RoleId> included,
        IReadOnlyDictionary<string, RoleDefinition> known,
        HashSet<string> visiting,
        HashSet<string> visited)
    {
        if (!visiting.Add(current))
            return true;
        foreach (var child in included)
        {
            if (string.Equals(child.Value, current, StringComparison.Ordinal))
                return true;
            if (known.TryGetValue(child.Value, out var definition)
                && Walk(child.Value, definition.IncludedRoles, known, visiting, visited))
                return true;
        }

        visiting.Remove(current);
        visited.Add(current);
        return false;
    }

    static bool WalkPermissions(
        RoleId roleId,
        Func<RoleId, RoleDefinition?> resolve,
        HashSet<PermissionId> permissions,
        HashSet<string> visiting,
        HashSet<string> visited)
    {
        if (!visited.Add(roleId.Value))
            return !visiting.Contains(roleId.Value);
        if (!visiting.Add(roleId.Value))
            return false;

        var definition = resolve(roleId);
        if (definition is null)
        {
            visiting.Remove(roleId.Value);
            return true;
        }

        foreach (var permission in definition.Permissions)
            permissions.Add(permission);
        foreach (var included in definition.IncludedRoles)
        {
            if (!WalkPermissions(included, resolve, permissions, visiting, visited))
                return false;
        }

        visiting.Remove(roleId.Value);
        return true;
    }
}
