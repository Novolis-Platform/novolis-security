namespace Novolis.Security.PasswordHashing;

/// <summary>Options for <see cref="PasswordHasher"/>.</summary>
public class PasswordHasherOptions
{
    /// <summary>PBKDF2 iteration count.</summary>
    public int Iterations { get; set; } = 10000;

    /// <summary>Salt size in bytes.</summary>
    public int SaltSize { get; set; } = 128;

    /// <summary>Derived key size in bytes.</summary>
    public int KeySize { get; set; } = 256;
}
