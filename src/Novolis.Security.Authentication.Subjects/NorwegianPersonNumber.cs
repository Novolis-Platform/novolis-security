using System.Diagnostics.CodeAnalysis;

namespace Novolis.Security.Authentication.Subjects;

/// <summary>Norwegian fødselsnummer / d-number (11 digits) validation and masking for owner UI.</summary>
public static class NorwegianPersonNumber
{
    /// <summary>Whether <paramref name="value"/> is exactly 11 digits with a valid check digit.</summary>
    public static bool IsValid(string? value) =>
        TryNormalize(value, out _);

    /// <summary>Strips spaces/separators and returns digits when the check digit is valid.</summary>
    public static bool TryNormalize(string? value, [NotNullWhen(true)] out string? digits)
    {
        digits = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        Span<char> buffer = stackalloc char[11];
        var count = 0;
        foreach (var ch in value)
        {
            if (ch is ' ' or '.' or '-')
            {
                continue;
            }

            if (ch is < '0' or > '9' || count >= 11)
            {
                return false;
            }

            buffer[count++] = ch;
        }

        if (count != 11)
        {
            return false;
        }

        var candidate = new string(buffer);
        if (!HasValidCheckDigit(candidate))
        {
            return false;
        }

        digits = candidate;
        return true;
    }

    private static bool HasValidCheckDigit(string digits)
    {
        // Individual number check (digit 10) then person number check (digit 11).
        int[] weights1 = [3, 7, 6, 1, 8, 9, 4, 5, 2];
        int[] weights2 = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
        var k1 = CheckDigit(digits, weights1);
        if (k1 is null || digits[9] - '0' != k1.Value)
        {
            return false;
        }

        var k2 = CheckDigit(digits, weights2);
        return k2 is not null && digits[10] - '0' == k2.Value;
    }

    private static int? CheckDigit(string digits, int[] weights)
    {
        var sum = 0;
        for (var i = 0; i < weights.Length; i++)
        {
            sum += (digits[i] - '0') * weights[i];
        }

        var mod = sum % 11;
        if (mod == 0)
        {
            return 0;
        }

        var check = 11 - mod;
        return check == 10 ? null : check;
    }
}
