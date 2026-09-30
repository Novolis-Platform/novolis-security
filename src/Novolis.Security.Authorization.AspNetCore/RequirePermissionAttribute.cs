namespace Novolis.Security.Authorization.AspNetCore;

/// <summary>Metadata-only permission requirement. Contains no authorization logic.</summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public sealed class RequirePermissionAttribute<TPermission> : Attribute, IPermissionRequirementMetadata
    where TPermission : IPermission
{
    /// <inheritdoc />
    public PermissionId Permission { get; } = AuthorizationIds.Permission<TPermission>();
}
