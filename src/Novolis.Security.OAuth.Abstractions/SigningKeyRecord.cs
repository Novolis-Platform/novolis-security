namespace Novolis.Security.OAuth;

/// <summary>ECDSA P-384 signing-key record used by the OAuth key ring.</summary>
public sealed class SigningKeyRecord
{
    /// <summary>Internal persistence key.</summary>
    public Guid Id { get; set; }

    /// <summary>JWT header <c>kid</c>.</summary>
    public string Kid { get; set; } = "";

    /// <summary>JWS algorithm. The initial implementation accepts only ES384.</summary>
    public string Alg { get; set; } = "ES384";

    /// <summary>Public JWK JSON for JWKS.</summary>
    public string PublicJwk { get; set; } = "";

    /// <summary>Optional private PEM for a host-managed secure store.</summary>
    public string? PrivatePem { get; set; }

    /// <summary>Optional encrypted private PEM.</summary>
    public string? PrivatePemCipher { get; set; }

    /// <summary>Key creation time.</summary>
    public DateTimeOffset CreatedUtc { get; set; }

    /// <summary>Time before which the key cannot be used.</summary>
    public DateTimeOffset? NotBeforeUtc { get; set; }

    /// <summary>Time after which the key is no longer published.</summary>
    public DateTimeOffset? NotAfterUtc { get; set; }

    /// <summary>Whether the key is available to the key ring.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Whether this key signs new access tokens.</summary>
    public bool Current { get; set; }
}
