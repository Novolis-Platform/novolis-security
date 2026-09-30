using Novolis.Storage.Abstractions;

namespace Novolis.Security.Authentication.Storage;

/// <summary>Identity-directory row. Contains no password hash or credential secret.</summary>
public sealed class StoredIdentity : IHasId
{
    /// <inheritdoc />
    public Guid Id { get; set; }

    /// <summary>Opaque credential locator.</summary>
    public Guid CredentialReference { get; set; }

    /// <summary>Normalized email when used as an identifier.</summary>
    public string? Email { get; set; }

    /// <summary>Normalized username when used as an identifier.</summary>
    public string? Username { get; set; }

    /// <summary>Optional display name.</summary>
    public string? DisplayName { get; set; }

    /// <summary>When true, authentication fails closed.</summary>
    public bool Disabled { get; set; }

    /// <summary>Creation time.</summary>
    public DateTimeOffset CreatedUtc { get; set; }
}
