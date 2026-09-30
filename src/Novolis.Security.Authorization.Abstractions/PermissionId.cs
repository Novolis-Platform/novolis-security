namespace Novolis.Security.Authorization;

/// <summary>Stable permission identifier used for persistence and evaluation.</summary>
public readonly record struct PermissionId(string Value)
{
    /// <inheritdoc />
    public override string ToString() => Value;
}
