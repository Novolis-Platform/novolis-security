namespace Novolis.Security.Authorization;

/// <summary>Stable role identifier used for persistence and evaluation.</summary>
public readonly record struct RoleId(string Value)
{
    /// <inheritdoc />
    public override string ToString() => Value;
}
