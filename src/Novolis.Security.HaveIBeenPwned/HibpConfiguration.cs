namespace Novolis.Security.HaveIBeenPwned;

/// <summary>Configuration for authenticated Have I Been Pwned REST calls. Range lookups ignore this type.</summary>
public class HibpConfiguration
{
    /// <summary>Optional HIBP API key for authenticated endpoints.</summary>
    public string ApiKey { get; set; } = string.Empty;

    /// <summary>Base URI for the HIBP REST API.</summary>
    public Uri BaseAddress { get; set; } = new Uri("https://haveibeenpwned.com/api/v3");

    /// <summary>Application name sent in API requests.</summary>
    public string ApplicationName { get; set; } = "HIBP.Toolkit";
}
