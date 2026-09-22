namespace Novolis.Security.Idp;

/// <summary>Persists RSA signing keys. Private PEM is optional; production hosts can supply PEM via <see cref="IdpOptions.SigningKeyPem"/>.</summary>
public interface ISigningKeyStore
{
    /// <summary>Active keys that have not expired.</summary>
    ValueTask<IReadOnlyList<IdpSigningKey>> GetActiveAsync(CancellationToken ct = default);

    /// <summary>Finds a key by JWT <c>kid</c>.</summary>
    ValueTask<IdpSigningKey?> GetByKidAsync(string kid, CancellationToken ct = default);

    /// <summary>Inserts or replaces a key.</summary>
    ValueTask UpsertAsync(IdpSigningKey key, CancellationToken ct = default);
}
