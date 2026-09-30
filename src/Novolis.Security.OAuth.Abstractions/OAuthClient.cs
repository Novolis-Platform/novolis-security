namespace Novolis.Security.OAuth;

/// <summary>OAuth client definition independent from any authenticated identity.</summary>
public sealed class OAuthClient
{
    /// <summary>Internal persistence key.</summary>
    public Guid Id { get; set; }

    /// <summary>Public client identifier sent as <c>client_id</c>.</summary>
    public string ClientId { get; set; } = "";

    /// <summary>Client authentication profile.</summary>
    public OAuthClientType ClientType { get; set; } = OAuthClientType.Confidential;

    /// <summary>Hashed client secret for confidential clients.</summary>
    public string SecretHash { get; set; } = "";

    /// <summary>When true, every grant is rejected.</summary>
    public bool Disabled { get; set; }

    /// <summary>Allowed grant-type values.</summary>
    public List<string> AllowedGrantTypes { get; set; } = [];

    /// <summary>Exact redirect URIs allowed for Authorization Code.</summary>
    public List<string> AllowedRedirectUris { get; set; } = [];

    /// <summary>Scopes the client may request or receive.</summary>
    public List<string> AllowedScopes { get; set; } = [];

    /// <summary>Audience allow-list. Empty means use configured server audiences.</summary>
    public List<string> AllowedAudiences { get; set; } = [];

    /// <summary>Whether this client may use a static secret.</summary>
    public bool IsConfidential => ClientType == OAuthClientType.Confidential;
}
