namespace Novolis.Security.Resources;

/// <summary>
/// The Characters class provides utility methods and predefined collections of characters.
/// </summary>
public static class Characters
{
    /// <summary>
    /// Retrieves a collection of all characters in the Unicode character set.
    /// </summary>
    /// <returns>A collection of all characters in the Unicode character set.</returns>
    public static IEnumerable<char> All() => Enumerable.Range(0, 65535).Select(i => (char)i).ToArray();
    
    /// <summary>
    /// Represents a list of uppercase characters.
    /// </summary>
    public static readonly IEnumerable<char> Uppercase = Enumerable.Range(65, 26).Select(i => (char)i).ToArray();

    /// <summary>
    /// Represents a list of lowercase letters.
    /// </summary>
    public static readonly IEnumerable<char> Lowercase = Enumerable.Range(97, 26).Select(i => (char)i).ToArray();

    /// <summary>
    /// Represents a list of digit characters.
    /// </summary>
    public static readonly IEnumerable<char> Digits = Enumerable.Range(48, 10).Select(i => (char)i).ToArray();

    /// <summary>
    /// Represents a list of special characters.
    /// </summary>
    public static readonly IEnumerable<char> Special = Enumerable.Range(32, 15).Select(i => (char)i).ToArray();
    
    /// <summary>
    /// Whitespace characters are characters that are not visible, but take up space.
    /// </summary>
    public static readonly IEnumerable<char> Whitespace = new[] { ' ' };
    
    /// <summary>
    /// Homoglyphs are characters that look similar to other characters (e.g. 0 and O).
    /// </summary>
    public static readonly IEnumerable<char> Homoglyphs = new[] { '0', '1', 'i', 'j', 'I', 'l', 'o', 'O' };
}