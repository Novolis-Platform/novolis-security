using Novolis.Storage.Abstractions;

namespace Novolis.Security.Idp;

/// <summary>ECDSA P-384 (ES384) signing key. Hosts should prefer PEM in <see cref="IdpOptions"/> over persisting private keys.</summary>
public sealed class IdpSigningKey : IHasId
{
    /// <inheritdoc />
    public Guid Id { get; set; }

    /// <summary>JWT header <c>kid</c>.</summary>
    public string Kid { get; set; } = "";

    /// <summary>JWS algorithm. Always <c>ES384</c> for this IDP.</summary>
    public string Alg { get; set; } = "ES384";

    /// <summary>Public JWK JSON for JWKS.</summary>
    public string PublicJwk { get; set; } = "";

    /// <summary>Optional PEM private key for in-memory/dev stores. Do not put plaintext PEM in durable JSON files.</summary>
    public string? PrivatePem { get; set; }

    /// <summary>Optional encrypted private PEM. Unused unless the host decrypts before signing.</summary>
    public string? PrivatePemCipher { get; set; }

    /// <summary>UTC creation timestamp.</summary>
    public DateTimeOffset CreatedUtc { get; set; }

    /// <summary>Optional expiry. Inactive after this instant.</summary>
    public DateTimeOffset? NotAfterUtc { get; set; }

    /// <summary>When false, the key is omitted from signing and JWKS.</summary>
    public bool Active { get; set; } = true;
}
