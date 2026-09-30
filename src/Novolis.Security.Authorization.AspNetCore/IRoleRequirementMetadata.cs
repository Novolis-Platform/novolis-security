namespace Novolis.Security.Authorization.AspNetCore;

/// <summary>Endpoint metadata describing a required assigned role.</summary>
public interface IRoleRequirementMetadata
{
    /// <summary>Required assigned role.</summary>
    RoleId Role { get; }
}
