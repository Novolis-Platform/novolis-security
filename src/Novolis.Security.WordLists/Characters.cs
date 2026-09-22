namespace Novolis.Security.WordLists;

/// <summary>Predefined character classes for secret generation. Collections are loaded once.</summary>
public sealed class Characters
{
    /// <summary>Process-wide instance.</summary>
    public static Characters Instance { get; } = new();

    Characters() { }

    /// <summary>Every BMP code point from 0 through 65534, cached.</summary>
    public static IReadOnlyList<char> All { get; } = CreateRange(0, 65535);

    /// <summary>A–Z.</summary>
    public static IReadOnlyList<char> Uppercase { get; } = CreateRange(65, 26);

    /// <summary>a–z.</summary>
    public static IReadOnlyList<char> Lowercase { get; } = CreateRange(97, 26);

    /// <summary>0–9.</summary>
    public static IReadOnlyList<char> Digits { get; } = CreateRange(48, 10);

    /// <summary>ASCII specials from space through <c>/</c>.</summary>
    public static IReadOnlyList<char> Special { get; } = CreateRange(32, 15);

    /// <summary>A single space.</summary>
    public static IReadOnlyList<char> Whitespace { get; } = [' '];

    /// <summary>Characters that are easy to confuse (0/O, 1/l/I, …).</summary>
    public static IReadOnlyList<char> Homoglyphs { get; } = ['0', '1', 'i', 'j', 'I', 'l', 'o', 'O'];

    static char[] CreateRange(int start, int count)
    {
        var chars = new char[count];
        for (var i = 0; i < count; i++)
            chars[i] = (char)(start + i);
        return chars;
    }
}
