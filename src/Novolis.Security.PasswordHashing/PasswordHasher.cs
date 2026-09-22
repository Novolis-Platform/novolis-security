using Konscious.Security.Cryptography;
using Microsoft.Extensions.Options;
using Novolis.Security.Cryptography;
using System.Text;

namespace Novolis.Security.PasswordHashing;

/// <summary>Argon2id password hasher with a self-describing PHC string (no legacy PBKDF2).</summary>
public class PasswordHasher(IOptions<PasswordHasherOptions> options)
{
    /// <summary>Hashes a password with a fresh salt. Format: <c>$argon2id$v=19$m=..,t=..,p=..$salt$hash</c>.</summary>
    /// <param name="password">Plain-text password.</param>
    public string HashPassword(string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);
        var o = options.Value;
        if (password.Length > o.MaxPasswordLength)
            throw new ArgumentOutOfRangeException(nameof(password), "Password exceeds MaxPasswordLength.");
        var salt = SecureRandom.GetBytes(o.SaltSize);
        var hash = Derive(password, salt, o.MemorySizeKiB, o.Iterations, o.DegreeOfParallelism, o.HashSize);
        return Encode(o.MemorySizeKiB, o.Iterations, o.DegreeOfParallelism, salt, hash);
    }

    /// <summary>Verifies <paramref name="password"/> against a PHC hash using fixed-time comparison.</summary>
    public bool CompareHashedPassword(string hashedPassword, string password)
    {
        if (string.IsNullOrEmpty(hashedPassword) || string.IsNullOrEmpty(password))
            return false;
        var o = options.Value;
        if (password.Length > o.MaxPasswordLength)
            return false;
        if (!TryDecode(hashedPassword, o, out var memory, out var iterations, out var parallelism, out var salt, out var expected))
            return false;

        var actual = Derive(password, salt, memory, iterations, parallelism, expected.Length);
        return ConstantTime.Equals(actual, expected);
    }

    private static byte[] Derive(string password, byte[] salt, int memoryKiB, int iterations, int parallelism, int hashSize)
    {
        var argon = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            MemorySize = memoryKiB,
            Iterations = iterations,
            DegreeOfParallelism = parallelism,
        };
        return argon.GetBytes(hashSize);
    }

    private static string Encode(int memoryKiB, int iterations, int parallelism, byte[] salt, byte[] hash) =>
        $"$argon2id$v=19$m={memoryKiB},t={iterations},p={parallelism}${B64(salt)}${B64(hash)}";

    private static bool TryDecode(
        string encoded,
        PasswordHasherOptions options,
        out int memoryKiB,
        out int iterations,
        out int parallelism,
        out byte[] salt,
        out byte[] hash)
    {
        memoryKiB = 0;
        iterations = 0;
        parallelism = 0;
        salt = [];
        hash = [];

        var parts = encoded.Split('$', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 5)
            return false;
        if (!string.Equals(parts[0], "argon2id", StringComparison.Ordinal))
            return false;
        if (!string.Equals(parts[1], "v=19", StringComparison.Ordinal))
            return false;

        var parms = parts[2].Split(',', StringSplitOptions.RemoveEmptyEntries);
        if (parms.Length != 3)
            return false;
        if (!parms[0].StartsWith("m=", StringComparison.Ordinal) || !int.TryParse(parms[0].AsSpan(2), out memoryKiB))
            return false;
        if (!parms[1].StartsWith("t=", StringComparison.Ordinal) || !int.TryParse(parms[1].AsSpan(2), out iterations))
            return false;
        if (!parms[2].StartsWith("p=", StringComparison.Ordinal) || !int.TryParse(parms[2].AsSpan(2), out parallelism))
            return false;
        if (memoryKiB < 8 || iterations < 1 || parallelism < 1)
            return false;
        if (memoryKiB > options.MaxVerifyMemoryKiB || iterations > options.MaxVerifyIterations || parallelism > 16)
            return false;

        try
        {
            salt = FromB64(parts[3]);
            hash = FromB64(parts[4]);
        }
        catch (FormatException)
        {
            return false;
        }

        return salt.Length >= 8 && hash.Length >= 16;
    }

    private static string B64(byte[] data) => Convert.ToBase64String(data).TrimEnd('=');

    private static byte[] FromB64(string value)
    {
        var pad = (4 - value.Length % 4) % 4;
        return Convert.FromBase64String(pad == 0 ? value : value + new string('=', pad));
    }
}
