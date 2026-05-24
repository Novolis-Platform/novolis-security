namespace Novolis.Security.HaveIBeenPwned;

/// <summary>Entry from the Pwned Passwords range API.</summary>
public class PasswordDetails
{
    /// <summary>Number of times this hash suffix was observed in breaches.</summary>
    public uint TimesPwned { get; set; } = 0;

    /// <summary>First five characters of the SHA-1 hash.</summary>
    public string Sha1Prefix { get; set; } = string.Empty;

    /// <summary>Remaining SHA-1 hash suffix.</summary>
    public string Sha1Suffix { get; set; } = string.Empty;

    /// <summary>Obsolete alias for <see cref="Sha1Suffix"/>.</summary>
    [Obsolete("Use Sha1Suffix. This property was misnamed and will be removed in a future release.")]
    public string Sha2Suffix
    {
        get => Sha1Suffix;
        set => Sha1Suffix = value;
    }

    /// <summary>Full SHA-1 hash (prefix + suffix).</summary>
    public string Sha1Hash { get; set; } = string.Empty;
}
