using Novolis.Security.Authentication;

namespace Novolis.Security.Authorization;

/// <summary>Tenant-scoped membership of an identity in a group.</summary>
public sealed record GroupMembership(
    TenantId TenantId,
    GroupId GroupId,
    IdentityId IdentityId);
