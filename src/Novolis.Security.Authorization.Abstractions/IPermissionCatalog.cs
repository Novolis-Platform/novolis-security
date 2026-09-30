namespace Novolis.Security.Authorization;

/// <summary>Application-registered permission identifiers.</summary>
public interface IPermissionCatalog
{
    /// <summary>Whether the application understands the permission.</summary>
    bool Contains(PermissionId permission);
}
