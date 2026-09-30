namespace Novolis.Security.Authorization;

/// <summary>Compile-time role contract.</summary>
public interface IRole
{
    /// <summary>Stable role identifier.</summary>
    static abstract string Value { get; }
}
