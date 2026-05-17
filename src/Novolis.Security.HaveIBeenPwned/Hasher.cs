using System.Security.Cryptography;
using System.Text;

namespace Novolis.Security.HaveIBeenPwned;

internal static class Hasher
{
    internal static string GetSha1(string s)
    {
        var bytes = Encoding.Default.GetBytes(s);
        var hashBytes = SHA1.HashData(bytes);
        return HexStringFromBytes(hashBytes);
    }

    private static string HexStringFromBytes(IEnumerable<byte> bytes)
    {
        var sb = new StringBuilder();
        foreach (var b in bytes)
        {
            var hex = b.ToString("X2");
            sb.Append(hex);
        }
        return sb.ToString();
    }
}