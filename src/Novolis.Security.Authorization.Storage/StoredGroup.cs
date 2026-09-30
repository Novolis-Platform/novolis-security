using Novolis.Storage.Abstractions;

namespace Novolis.Security.Authorization.Storage;

/// <summary>Persisted group row.</summary>
public sealed class StoredGroup : IHasId
{
    /// <inheritdoc />
    public Guid Id { get; set; }

    /// <summary>Owning tenant.</summary>
    public Guid TenantId { get; set; }

    /// <summary>Group name.</summary>
    public string Name { get; set; } = "";
}
