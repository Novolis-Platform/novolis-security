namespace Novolis.Security.Authorization;

/// <summary>Conversions from generic static members to runtime value types.</summary>
public static class AuthorizationIds
{
    /// <summary>Gets the runtime permission id for a compile-time permission.</summary>
    public static PermissionId Permission<TPermission>()
        where TPermission : IPermission =>
        new(TPermission.Value);

    /// <summary>Gets the runtime role id for a compile-time role.</summary>
    public static RoleId Role<TRole>()
        where TRole : IRole =>
        new(TRole.Value);
}
