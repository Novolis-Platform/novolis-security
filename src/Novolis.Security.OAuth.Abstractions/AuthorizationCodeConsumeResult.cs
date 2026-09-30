namespace Novolis.Security.OAuth;

/// <summary>Outcome of an atomic Authorization Code redemption attempt.</summary>
public sealed class AuthorizationCodeConsumeResult
{
    /// <summary>Whether a code was atomically consumed.</summary>
    public bool Succeeded { get; init; }

    /// <summary>Consumed record on success.</summary>
    public AuthorizationCodeRecord? Record { get; init; }

    /// <summary>Whether the code was already consumed.</summary>
    public bool WasReplayed { get; init; }

    /// <summary>Creates a successful result.</summary>
    public static AuthorizationCodeConsumeResult Success(AuthorizationCodeRecord record) =>
        new() { Succeeded = true, Record = record };

    /// <summary>Creates a failed result.</summary>
    public static AuthorizationCodeConsumeResult Failure(bool replayed = false) =>
        new() { WasReplayed = replayed };
}
