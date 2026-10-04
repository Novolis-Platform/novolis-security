namespace Novolis.Security.HaveIBeenPwned;

/// <summary>Configuration for <see cref="HaveIBeenPwnedClient"/>.</summary>
public class HibpConfiguration
{
    /// <summary>Optional HIBP API key for authenticated endpoints.</summary>
    public string ApiKey { get; set; } = string.Empty;

    /// <summary>Base URI for the HIBP REST API.</summary>
    public Uri BaseAddress { get; set; } = new Uri("https://haveibeenpwned.com/api/v3");

    /// <summary>Unused for range lookups. The named <see cref="PwnedPasswordsApi"/> client is pinned to api.pwnedpasswords.com.</summary>
    public Uri PwnedPasswordAddress { get; set; } = new Uri("https://api.pwnedpasswords.com/range");

    /// <summary>Application name sent in API requests.</summary>
    public string ApplicationName { get; set; } = "HIBP.Toolkit";
}
