using Novolis.Storage.Abstractions;

namespace Novolis.Security.Authentication.Storage;

/// <summary>Credential-vault row. Contains no identity, login, tenant, or authorization fields.</summary>
public sealed class StoredCredential : IHasId
{
    /// <inheritdoc />
    public Guid Id { get; set; }

    /// <summary>Opaque credential locator.</summary>
    public Guid Reference { get; set; }

    /// <summary>Password hash.</summary>
    public string PasswordHash { get; set; } = "";

    /// <summary>When true, verification fails closed.</summary>
    public bool Disabled { get; set; }

    /// <summary>Creation time.</summary>
    public DateTimeOffset CreatedUtc { get; set; }

    /// <summary>Update time.</summary>
    public DateTimeOffset UpdatedUtc { get; set; }
}
