namespace Novolis.Security.OAuth;

/// <summary>Outcome of an atomic refresh-token rotation.</summary>
public sealed class RefreshRotationResult
{
    /// <summary>Whether the replacement was committed.</summary>
    public bool Succeeded { get; init; }

    /// <summary>Whether the presented token had already been spent.</summary>
    public bool WasReplayed { get; init; }

    /// <summary>Creates a successful result.</summary>
    public static RefreshRotationResult Success() => new() { Succeeded = true };

    /// <summary>Creates a failed result.</summary>
    public static RefreshRotationResult Failure(bool replayed = false) =>
        new() { WasReplayed = replayed };
}
