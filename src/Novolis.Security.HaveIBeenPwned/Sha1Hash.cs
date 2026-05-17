namespace Novolis.Security.HaveIBeenPwned;

internal class Sha1Hash(string source)
{
    public string Prefix => Hash[..5];
    public string Suffix => Hash[5..];
    public string Hash { get; } = Hasher.GetSha1(source);
}