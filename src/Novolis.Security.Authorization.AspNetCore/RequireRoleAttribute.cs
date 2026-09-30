namespace Novolis.Security.Authorization.AspNetCore;

/// <summary>Metadata-only assigned-role requirement. Contains no authorization logic.</summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public sealed class RequireRoleAttribute<TRole> : Attribute, IRoleRequirementMetadata
    where TRole : IRole
{
    /// <inheritdoc />
    public RoleId Role { get; } = AuthorizationIds.Role<TRole>();
}
