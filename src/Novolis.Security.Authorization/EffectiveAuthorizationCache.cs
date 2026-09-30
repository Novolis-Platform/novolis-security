using System.Collections.Concurrent;
using Novolis.Security.Authentication;

namespace Novolis.Security.Authorization;

/// <summary>Short-lived cache keyed by tenant, identity, and authorization version.</summary>
public sealed class EffectiveAuthorizationCache
{
    readonly ConcurrentDictionary<string, EffectiveAuthorization> _entries = new(StringComparer.Ordinal);

    /// <summary>Tries to read a cached evaluation.</summary>
    public bool TryGet(
        TenantId tenantId,
        IdentityId identityId,
        long version,
        out EffectiveAuthorization? value) =>
        _entries.TryGetValue(Key(tenantId, identityId, version), out value);

    /// <summary>Stores a cached evaluation.</summary>
    public void Set(
        TenantId tenantId,
        IdentityId identityId,
        long version,
        EffectiveAuthorization value) =>
        _entries[Key(tenantId, identityId, version)] = value;

    static string Key(TenantId tenantId, IdentityId identityId, long version) =>
        $"{tenantId.Value:N}:{identityId.Value:N}:{version}";
}
