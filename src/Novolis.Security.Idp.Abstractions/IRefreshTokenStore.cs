namespace Novolis.Security.Idp;

/// <summary>Persists hashed refresh tokens. Lookups are by <see cref="IdpRefreshToken.Id"/> so the wire format can be <c>{id}.{secret}</c>.</summary>
public interface IRefreshTokenStore
{
    /// <summary>Gets a refresh row by id.</summary>
    ValueTask<IdpRefreshToken?> TryGetAsync(Guid id, CancellationToken ct = default);

    /// <summary>Inserts or replaces a refresh row.</summary>
    ValueTask UpsertAsync(IdpRefreshToken token, CancellationToken ct = default);

    /// <summary>All rows in a rotation family (for reuse revocation).</summary>
    ValueTask<IReadOnlyList<IdpRefreshToken>> FindByFamilyIdAsync(Guid familyId, CancellationToken ct = default);

    /// <summary>
    /// Revokes <paramref name="currentId"/> and inserts <paramref name="replacement"/> only if the current row is still unrevoked.
    /// Returns <see langword="false"/> when the current token is missing or already spent (caller must revoke the family).
    /// </summary>
    ValueTask<bool> TryRotateAsync(Guid currentId, IdpRefreshToken replacement, CancellationToken ct = default);
}
