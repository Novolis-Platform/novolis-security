namespace Novolis.Security.Idp;

/// <summary>
/// Signing-key persistence for ES384. Rotation shape: keep retired keys <see cref="IdpSigningKey.Active"/>
/// for validation until <see cref="IdpSigningKey.NotAfterUtc"/>, and mint only with a row that still has private material.
/// </summary>
public interface IKeyStore
{
    /// <summary>Keys that may appear in JWKS (active and not past <c>NotAfterUtc</c>).</summary>
    ValueTask<IReadOnlyList<IdpSigningKey>> GetActiveAsync(CancellationToken ct = default);

    /// <summary>Finds a key by JWT <c>kid</c>.</summary>
    ValueTask<IdpSigningKey?> GetByKidAsync(string kid, CancellationToken ct = default);

    /// <summary>Inserts or replaces a key.</summary>
    ValueTask UpsertAsync(IdpSigningKey key, CancellationToken ct = default);
}
