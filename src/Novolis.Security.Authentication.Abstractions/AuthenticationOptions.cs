namespace Novolis.Security.Authentication;

/// <summary>Application authentication and browser-session defaults.</summary>
public sealed class AuthenticationOptions
{
    /// <summary>How long a browser authentication session remains valid.</summary>
    public TimeSpan SessionLifetime { get; set; } = TimeSpan.FromHours(8);

    /// <summary>Whether a sign-in creates a browser session by default.</summary>
    public bool CreateSessionByDefault { get; set; } = true;

    /// <summary>Minimum password length accepted by <c>RegisterAsync</c>. Values below 8 are raised to 8.</summary>
    public int MinimumPasswordLength { get; set; } = 8;

    /// <summary>Whether the host is running in Development. A missing breach checker is allowed only then.</summary>
    public bool IsDevelopment { get; set; }

    /// <summary>
    /// Idle lifetime after the last successful session lookup. Absolute <see cref="SessionLifetime"/> still applies.
    /// </summary>
    public TimeSpan SessionIdleTimeout { get; set; } = TimeSpan.FromMinutes(20);

    /// <summary>
    /// Substrings that must not appear in a new password, compared without regard to case.
    /// Hosts add product and organization names (ASVS 6.2.11). The identifier is always forbidden as well.
    /// </summary>
    public string[] ForbiddenPasswordFragments { get; set; } = [];

    /// <summary>
    /// Failed sign-in attempts against one credential before it is disabled.
    /// The count lives in <see cref="ICacheStore"/> so a farm shares the same window.
    /// </summary>
    public int MaxSignInFailures { get; set; } = 5;

    /// <summary>Sliding window for <see cref="MaxSignInFailures"/>.</summary>
    public TimeSpan SignInFailureWindow { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>OAuth issuer composed by the high-level ASP.NET façade.</summary>
    public Uri? Issuer { get; set; }
}
