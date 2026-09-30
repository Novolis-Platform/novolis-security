namespace Novolis.Security.Authorization;

/// <summary>Compile-time permission contract. The string value is the runtime identity.</summary>
public interface IPermission
{
    /// <summary>Stable permission identifier.</summary>
    static abstract string Value { get; }
}
