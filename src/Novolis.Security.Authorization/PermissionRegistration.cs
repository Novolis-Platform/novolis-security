namespace Novolis.Security.Authorization;

internal sealed class PermissionRegistration<TPermission> : IPermissionRegistration
    where TPermission : IPermission
{
    public PermissionId Permission { get; } = AuthorizationIds.Permission<TPermission>();
}
