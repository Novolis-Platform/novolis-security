namespace Novolis.Security.Authentication;

/// <summary>Credential-vault record containing no identity-directory or authorization data.</summary>
public sealed class CredentialRecord
{
    /// <summary>Internal persistence key. It is not a public identity or credential reference.</summary>
    public Guid StorageId { get; set; } = Guid.NewGuid();

    /// <summary>Opaque locator used by the identity directory.</summary>
    public CredentialReference Reference { get; set; }

    /// <summary>Password hash produced by the configured password hasher.</summary>
    public string PasswordHash { get; set; } = "";

    /// <summary>When true, verification fails closed.</summary>
    public bool Disabled { get; set; }

    /// <summary>Credential creation time.</summary>
    public DateTimeOffset CreatedUtc { get; set; }

    /// <summary>Most recent credential update time.</summary>
    public DateTimeOffset UpdatedUtc { get; set; }
}
