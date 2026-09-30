namespace Novolis.Security.OAuth;

/// <summary>Signing-key persistence for ES384 and historical validation keys.</summary>
public interface IKeyStore
{
    /// <summary>Keys that may appear in JWKS at the supplied instant.</summary>
    ValueTask<IReadOnlyList<SigningKeyRecord>> GetActiveAsync(
        DateTimeOffset now,
        CancellationToken ct = default);

    /// <summary>Gets the one current signing key.</summary>
    ValueTask<SigningKeyRecord?> GetCurrentAsync(
        DateTimeOffset now,
        CancellationToken ct = default);

    /// <summary>Finds a key by JWT <c>kid</c>.</summary>
    ValueTask<SigningKeyRecord?> GetByKidAsync(string kid, CancellationToken ct = default);

    /// <summary>Inserts or replaces a key.</summary>
    ValueTask UpsertAsync(SigningKeyRecord key, CancellationToken ct = default);
}
