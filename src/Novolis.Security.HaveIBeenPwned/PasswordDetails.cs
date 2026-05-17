namespace Novolis.Security.HaveIBeenPwned;

public class PasswordDetails
{
    public uint TimesPwned { get; set; } = 0;
    public string Sha1Prefix { get; set; } = string.Empty;
    public string Sha2Suffix { get; set; } = string.Empty;
    public string Sha1Hash { get; set; } = string.Empty;
}