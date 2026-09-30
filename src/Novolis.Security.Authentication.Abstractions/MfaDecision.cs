namespace Novolis.Security.Authentication;

/// <summary>Outcome of a second-factor check.</summary>
public sealed class MfaDecision
{
    /// <summary>Whether the second factor succeeded or was not required.</summary>
    public bool Succeeded { get; init; }

    /// <summary>Non-sensitive failure category such as <c>mfa_required</c> or <c>mfa_invalid</c>.</summary>
    public string? Error { get; init; }

    /// <summary>Creates a successful decision.</summary>
    public static MfaDecision Ok() => new() { Succeeded = true };

    /// <summary>Creates a failed decision.</summary>
    public static MfaDecision Fail(string error) =>
        new() { Error = error };
}
