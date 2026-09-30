namespace Novolis.Security.Authorization;

/// <summary>Positive-permission authorization outcome. Default is deny.</summary>
public sealed class AuthorizationDecision
{
    /// <summary>Whether the operation is allowed.</summary>
    public bool Succeeded { get; init; }

    /// <summary>Optional non-sensitive failure reason.</summary>
    public string? Reason { get; init; }

    /// <summary>Creates an allow decision.</summary>
    public static AuthorizationDecision Allow() => new() { Succeeded = true };

    /// <summary>Creates a deny decision.</summary>
    public static AuthorizationDecision Deny(string reason = "denied") =>
        new() { Reason = reason };
}
