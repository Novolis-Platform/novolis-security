namespace Novolis.Security.PasswordHashing;

/// <summary>Argon2id parameters. Defaults follow the OWASP 2024 first recommendation (19 MiB, t=2, p=1).</summary>
public class PasswordHasherOptions
{
    /// <summary>Memory cost in KiB. Default 19456 (19 MiB).</summary>
    public int MemorySizeKiB { get; set; } = 19_456;

    /// <summary>Time cost (passes). Default 2.</summary>
    public int Iterations { get; set; } = 2;

    /// <summary>Lane count. Default 1.</summary>
    public int DegreeOfParallelism { get; set; } = 1;

    /// <summary>Salt size in bytes. Default 16.</summary>
    public int SaltSize { get; set; } = 16;

    /// <summary>Derived key size in bytes. Default 32.</summary>
    public int HashSize { get; set; } = 32;

    /// <summary>Reject passwords longer than this (Argon2 DoS guard). Default 1024 characters.</summary>
    public int MaxPasswordLength { get; set; } = 1024;

    /// <summary>Refuse to verify PHC strings that request more memory than this (KiB). Default 65536.</summary>
    public int MaxVerifyMemoryKiB { get; set; } = 65_536;

    /// <summary>Refuse to verify PHC strings with more iterations than this. Default 12.</summary>
    public int MaxVerifyIterations { get; set; } = 12;
}
