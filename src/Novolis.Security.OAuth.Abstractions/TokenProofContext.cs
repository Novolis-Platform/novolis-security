namespace Novolis.Security.OAuth;

/// <summary>Proof presented with a token request or resource-server validation.</summary>
public sealed class TokenProofContext
{
    /// <summary>RFC 9449 DPoP proof JWT.</summary>
    public string? DPoPProof { get; init; }

    /// <summary>HTTP method the proof was created for.</summary>
    public string HttpMethod { get; init; } = "POST";

    /// <summary>HTTP URI the proof was created for, without a query string.</summary>
    public string HttpUri { get; init; } = "";

    /// <summary>SHA-256 thumbprint of a client certificate, Base64URL, for <c>cnf.x5t#S256</c>.</summary>
    public string? CertificateThumbprintSha256 { get; init; }
}
