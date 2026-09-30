using Novolis.Storage.Abstractions;

namespace Novolis.Security.Authorization.Storage;

/// <summary>Persisted tenant authorization version.</summary>
public sealed class StoredAuthorizationVersion : IHasId
{
    /// <inheritdoc />
    public Guid Id { get; set; }

    /// <summary>Monotonic version.</summary>
    public long Version { get; set; }
}
