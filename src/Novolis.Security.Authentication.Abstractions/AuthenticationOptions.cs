namespace Novolis.Security.Authentication;

/// <summary>Application authentication and browser-session defaults.</summary>
public sealed class AuthenticationOptions
{
    /// <summary>How long a browser authentication session remains valid.</summary>
    public TimeSpan SessionLifetime { get; set; } = TimeSpan.FromHours(8);

    /// <summary>Whether a sign-in creates a browser session by default.</summary>
    public bool CreateSessionByDefault { get; set; } = true;

    /// <summary>OAuth issuer composed by the high-level ASP.NET façade.</summary>
    public Uri? Issuer { get; set; }
}
