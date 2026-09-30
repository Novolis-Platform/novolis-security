namespace Novolis.Security.Authentication;

/// <summary>Application-neutral identity-directory record.</summary>
public sealed class IdentityRecord
{
    /// <summary>Global authenticated identity.</summary>
    public IdentityId Id { get; set; }

    /// <summary>Opaque reference to the separate credential vault.</summary>
    public CredentialReference CredentialReference { get; set; }

    /// <summary>Normalized email when the application uses email identifiers.</summary>
    public string? Email { get; set; }

    /// <summary>Normalized username when the application uses username identifiers.</summary>
    public string? Username { get; set; }

    /// <summary>Optional display name.</summary>
    public string? DisplayName { get; set; }

    /// <summary>When true, authentication fails closed.</summary>
    public bool Disabled { get; set; }

    /// <summary>Creation time supplied by the authentication service clock.</summary>
    public DateTimeOffset CreatedUtc { get; set; }
}
