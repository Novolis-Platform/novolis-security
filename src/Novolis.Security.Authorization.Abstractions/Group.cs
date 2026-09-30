namespace Novolis.Security.Authorization;

/// <summary>Named set of identities inside one tenant. Groups do not contain permissions.</summary>
public sealed record Group(
    GroupId Id,
    TenantId TenantId,
    string Name);
