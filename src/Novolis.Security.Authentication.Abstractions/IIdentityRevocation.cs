namespace Novolis.Security.Authentication;

/// <summary>
/// Notified when an identity signs out or is disabled. OAuth registers an implementation that
/// revokes refresh families; Authentication never references OAuth.
/// </summary>
public interface IIdentityRevocation
{
    /// <summary>Revokes tokens and other grants issued to <paramref name="identityId"/>.</summary>
    ValueTask RevokeAsync(
        IdentityId identityId,
        DateTimeOffset revokedUtc,
        CancellationToken cancellationToken = default);
}
