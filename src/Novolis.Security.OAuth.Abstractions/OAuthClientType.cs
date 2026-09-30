namespace Novolis.Security.OAuth;

/// <summary>OAuth client authentication profile.</summary>
public enum OAuthClientType
{
    /// <summary>Client that cannot safely keep a secret.</summary>
    Public = 0,

    /// <summary>Client that authenticates with a configured secret.</summary>
    Confidential = 1,
}
