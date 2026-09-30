namespace Novolis.Security.Authorization.AspNetCore;

/// <summary>Endpoint metadata describing a required permission.</summary>
public interface IPermissionRequirementMetadata
{
    /// <summary>Required permission.</summary>
    PermissionId Permission { get; }
}
