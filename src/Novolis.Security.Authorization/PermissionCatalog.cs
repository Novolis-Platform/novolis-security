namespace Novolis.Security.Authorization;

/// <summary>In-process catalog of application-understood permissions.</summary>
public sealed class PermissionCatalog : IPermissionCatalog
{
    readonly HashSet<PermissionId> _permissions = [];

    /// <summary>Registers a compile-time permission.</summary>
    public void Add<TPermission>()
        where TPermission : IPermission =>
        _permissions.Add(AuthorizationIds.Permission<TPermission>());

    /// <summary>Registers a runtime permission identifier.</summary>
    public void Add(PermissionId permission) => _permissions.Add(permission);

    /// <inheritdoc />
    public bool Contains(PermissionId permission) => _permissions.Contains(permission);
}
