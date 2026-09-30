namespace Novolis.Security.Authorization;

/// <summary>Authorization partition. It is never inferred from an identity.</summary>
public readonly record struct TenantId(Guid Value)
{
    /// <summary>Creates a new tenant identifier.</summary>
    public static TenantId New() => new(Guid.NewGuid());

    /// <inheritdoc />
    public override string ToString() => Value.ToString("D");
}
