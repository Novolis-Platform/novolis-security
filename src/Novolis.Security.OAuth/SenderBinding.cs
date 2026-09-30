namespace Novolis.Security.OAuth;

/// <summary>Sender constraint captured from a DPoP proof or client-certificate thumbprint.</summary>
internal sealed class SenderBinding
{
    public bool Succeeded { get; init; }
    public string? Jkt { get; init; }
    public string? X5tS256 { get; init; }

    public static SenderBinding Fail() => new();

    public static SenderBinding FromDPoP(string jkt) =>
        new() { Succeeded = true, Jkt = jkt };

    public static SenderBinding FromCertificate(string thumbprint) =>
        new() { Succeeded = true, X5tS256 = thumbprint };
}
