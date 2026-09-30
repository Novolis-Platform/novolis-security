namespace Novolis.Security.OAuth;

/// <summary>Persists hashed refresh tokens with atomic rotation operations.</summary>
public interface IRefreshTokenStore
{
    /// <summary>Gets a refresh row by id.</summary>
    ValueTask<RefreshTokenRecord?> TryGetAsync(Guid id, CancellationToken ct = default);

    /// <summary>Inserts or replaces a refresh row.</summary>
    ValueTask UpsertAsync(RefreshTokenRecord token, CancellationToken ct = default);

    /// <summary>All rows in a rotation family (for reuse revocation).</summary>
    ValueTask<IReadOnlyList<RefreshTokenRecord>> FindByFamilyIdAsync(Guid familyId, CancellationToken ct = default);

    /// <summary>
    /// Revokes <paramref name="currentId"/> and inserts <paramref name="replacement"/> only if
    /// the current row is still active and unexpired.
    /// </summary>
    ValueTask<RefreshRotationResult> TryRotateAsync(
        Guid currentId,
        RefreshTokenRecord replacement,
        DateTimeOffset now,
        CancellationToken ct = default);

    /// <summary>Revokes an individual token.</summary>
    ValueTask RevokeAsync(Guid tokenId, DateTimeOffset revokedUtc, CancellationToken ct = default);

    /// <summary>Revokes every token in a rotation family.</summary>
    ValueTask RevokeFamilyAsync(Guid familyId, DateTimeOffset revokedUtc, CancellationToken ct = default);
}
