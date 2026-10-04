using System.Security.Cryptography;

namespace Novolis.Security.OAuth.Client;

/// <summary>Client-credentials grant for a Novolis mint. Confidential and DPoP are separate factories.</summary>
public sealed class ClientCredentialsCredential
{
    private ClientCredentialsCredential(
        Uri issuer,
        string clientId,
        string scope,
        string? clientSecret,
        ECDsa? dPoPSigningKey,
        Uri? tokenEndpoint)
    {
        Issuer = issuer;
        ClientId = clientId;
        Scope = scope;
        ClientSecret = clientSecret;
        DPoPSigningKey = dPoPSigningKey;
        TokenEndpoint = tokenEndpoint;
    }

    /// <summary>Authorization-server issuer used for discovery.</summary>
    public Uri Issuer { get; }

    /// <summary>OAuth client identifier.</summary>
    public string ClientId { get; }

    /// <summary>Requested scope.</summary>
    public string Scope { get; }

    /// <summary>Client secret when this is a confidential credential.</summary>
    public string? ClientSecret { get; }

    /// <summary>ES256 P-256 key when this is a DPoP credential.</summary>
    public ECDsa? DPoPSigningKey { get; }

    /// <summary>Explicit token endpoint. When omitted, discovery supplies it.</summary>
    public Uri? TokenEndpoint { get; }

    /// <summary>Creates a confidential client-credentials credential.</summary>
    /// <param name="issuer">Issuer used for discovery.</param>
    /// <param name="clientId">OAuth client identifier.</param>
    /// <param name="clientSecret">Client secret.</param>
    /// <param name="scope">Requested scope.</param>
    /// <param name="tokenEndpoint">Optional absolute token endpoint. When omitted, discovery supplies it.</param>
    /// <returns>The credential.</returns>
    public static ClientCredentialsCredential Confidential(
        Uri issuer,
        string clientId,
        string clientSecret,
        string scope,
        Uri? tokenEndpoint = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientSecret);
        return new ClientCredentialsCredential(
            issuer,
            clientId,
            scope,
            clientSecret,
            dPoPSigningKey: null,
            tokenEndpoint);
    }

    /// <summary>Creates a DPoP client-credentials credential. There is no secret parameter.</summary>
    /// <param name="issuer">Issuer used for discovery.</param>
    /// <param name="clientId">OAuth client identifier.</param>
    /// <param name="dPoPSigningKey">ES256 P-256 signing key.</param>
    /// <param name="scope">Requested scope.</param>
    /// <param name="tokenEndpoint">Optional absolute token endpoint. When omitted, discovery supplies it.</param>
    /// <returns>The credential.</returns>
    public static ClientCredentialsCredential DPoP(
        Uri issuer,
        string clientId,
        ECDsa dPoPSigningKey,
        string scope,
        Uri? tokenEndpoint = null)
    {
        ArgumentNullException.ThrowIfNull(dPoPSigningKey);
        return new ClientCredentialsCredential(
            issuer,
            clientId,
            scope,
            clientSecret: null,
            dPoPSigningKey,
            tokenEndpoint);
    }
}
