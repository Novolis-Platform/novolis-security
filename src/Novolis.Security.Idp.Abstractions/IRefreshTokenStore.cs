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
}
