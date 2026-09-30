namespace Novolis.Security.Authorization;

/// <summary>Code-backed role with an immutable permission set.</summary>
public interface IBuiltInRole : IRole
{
    /// <summary>Permissions contained by the built-in role.</summary>
    static abstract IReadOnlySet<PermissionId> Permissions { get; }
}
