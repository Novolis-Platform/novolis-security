namespace Novolis.Security.HaveIBeenPwned;

public class HibpConfiguration
{
    public string ApiKey { get; set; } = string.Empty;
    public Uri BaseAddress { get; set; } = new Uri("https://haveibeenpwned.com/api/v3");
    public Uri PwnedPasswordAddress { get; set; } = new Uri("https://api.pwnedpasswords.com/range");
    public string ApplicationName { get; set; } = "HIBP.Toolkit";
}