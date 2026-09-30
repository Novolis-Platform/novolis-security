namespace Novolis.Security.Authorization;

/// <summary>Tenant-scoped group identifier.</summary>
public readonly record struct GroupId(Guid Value)
{
    /// <summary>Creates a new group identifier.</summary>
    public static GroupId New() => new(Guid.NewGuid());

    /// <inheritdoc />
    public override string ToString() => Value.ToString("D");
}
