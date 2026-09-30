using Novolis.Storage.Abstractions;

namespace Novolis.Security.OAuth.Storage;

/// <summary>SQLite-safe signing-key row.</summary>
public sealed class StoredSigningKey : IHasId
{
    /// <inheritdoc />
    public Guid Id { get; set; }

    /// <summary>Stable key id.</summary>
    public string Kid { get; set; } = "";

    /// <summary>JWS algorithm.</summary>
    public string Alg { get; set; } = "ES384";

    /// <summary>Public JWK JSON.</summary>
    public string PublicJwk { get; set; } = "";

    /// <summary>Optional private PEM.</summary>
    public string? PrivatePem { get; set; }

    /// <summary>Optional encrypted private PEM.</summary>
    public string? PrivatePemCipher { get; set; }

    /// <summary>Creation time.</summary>
    public DateTimeOffset CreatedUtc { get; set; }

    /// <summary>Not-before time.</summary>
    public DateTimeOffset? NotBeforeUtc { get; set; }

    /// <summary>Not-after time.</summary>
    public DateTimeOffset? NotAfterUtc { get; set; }

    /// <summary>Whether the key is published.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Whether the key signs new tokens.</summary>
    public bool Current { get; set; }
}
