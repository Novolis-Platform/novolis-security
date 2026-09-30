using Microsoft.Extensions.Options;
using Novolis.Security.Authentication;

namespace Novolis.Security.OAuth;

/// <summary>Revokes refresh families and records an identity not-before cutoff for access tokens.</summary>
public sealed class IdentityOAuthRevocation(
    IRefreshTokenStore refresh,
    ICacheStore cache,
    IOptions<OAuthOptions> options) : IIdentityRevocation
{
    /// <inheritdoc />
    public async ValueTask RevokeAsync(
        IdentityId identityId,
        DateTimeOffset revokedUtc,
        CancellationToken cancellationToken = default)
    {
        var rows = await refresh.FindByIdentityIdAsync(identityId, cancellationToken).ConfigureAwait(false);
        foreach (var familyId in rows.Select(row => row.FamilyId).Distinct())
            await refresh.RevokeFamilyAsync(familyId, revokedUtc, cancellationToken).ConfigureAwait(false);

        var ttl = options.Value.AccessTokenLifetime + options.Value.ClockSkew + TimeSpan.FromMinutes(1);
        await cache.SetAsync(
            "oauth:nbf:" + identityId,
            revokedUtc.ToUnixTimeSeconds(),
            ttl,
            cancellationToken).ConfigureAwait(false);
    }
}
