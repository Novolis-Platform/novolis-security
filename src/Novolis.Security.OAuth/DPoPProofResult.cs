namespace Novolis.Security.OAuth;

/// <summary>Outcome of a DPoP proof check.</summary>
public sealed class DPoPProofResult
{
    /// <summary>Whether the proof was accepted.</summary>
    public bool Succeeded { get; init; }

    /// <summary>RFC 7638 thumbprint of the proof public key.</summary>
    public string? Jkt { get; init; }

    /// <summary>Proof JWT id, used once.</summary>
    public string? Jti { get; init; }

    /// <summary>Creates a successful result.</summary>
    public static DPoPProofResult Ok(string jkt, string jti) =>
        new() { Succeeded = true, Jkt = jkt, Jti = jti };

    /// <summary>Creates a failed result.</summary>
    public static DPoPProofResult Fail() => new();
}
