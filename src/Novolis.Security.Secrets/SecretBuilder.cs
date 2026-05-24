using System.Text;
using Novolis.Security.Secrets.Internals;
using Novolis.Security.WordLists;

namespace Novolis.Security.Secrets;

/// <summary>Builds a random string from selected character classes.</summary>
public class SecretBuilder(int secretLength)
{
    private readonly List<char> _characters = [];
    private uint _shuffleCount;

    /// <summary>Creates a secret using <see cref="SecretGeneratorOptions"/>.</summary>
    public static string GenerateFromSettings(SecretGeneratorOptions options)
    {
        var builder = new SecretBuilder(options.Length);
        if (options.IncludeUppercase)
            builder.IncludeUppercase();
        if (options.IncludeLowercase)
            builder.IncludeLowercase();
        if (options.IncludeDigits)
            builder.IncludeDigits();
        if (options.IncludeSpecial)
            builder.IncludeSpecial();
        if (options.IncludeHomoglyphs)
            builder.IncludeHomoglyphs();
        if (options.IncludeWhitespace)
            builder.IncludeWhitespace();
        builder.Shuffle();
        return builder.Build();
    }

    /// <summary>Adds uppercase letters (excluding homoglyphs unless requested).</summary>
    public SecretBuilder IncludeUppercase()
    {
        _characters.AddRange(Characters.Uppercase.Except(Characters.Homoglyphs));
        return this;
    }

    /// <summary>Adds lowercase letters.</summary>
    public SecretBuilder IncludeLowercase()
    {
        _characters.AddRange(Characters.Lowercase.Except(Characters.Homoglyphs));
        return this;
    }

    /// <summary>Adds digit characters.</summary>
    public SecretBuilder IncludeDigits()
    {
        _characters.AddRange(Characters.Digits.Except(Characters.Homoglyphs));
        return this;
    }

    /// <summary>Adds special characters.</summary>
    public SecretBuilder IncludeSpecial()
    {
        _characters.AddRange(Characters.Special.Except(Characters.Homoglyphs));
        return this;
    }

    /// <summary>Adds homoglyph characters.</summary>
    public SecretBuilder IncludeHomoglyphs()
    {
        _characters.AddRange(Characters.Homoglyphs);
        return this;
    }

    /// <summary>Adds whitespace characters.</summary>
    public SecretBuilder IncludeWhitespace()
    {
        _characters.AddRange(Characters.Whitespace);
        return this;
    }

    /// <summary>Clears the character pool.</summary>
    public SecretBuilder Reset()
    {
        _characters.Clear();
        return this;
    }

    /// <summary>Shuffles the character pool before sampling.</summary>
    public SecretBuilder Shuffle(uint shuffleCount = 1)
    {
        _shuffleCount = shuffleCount;
        return this;
    }

    /// <summary>Builds the final secret string.</summary>
    public string Build()
    {
        if (_characters.Count == 0)
            throw new InvalidOperationException("No character sets were included. Call Include* methods before Build().");

        var stringBuilder = new StringBuilder();
        _characters.Shuffle(_shuffleCount);
        for (var i = 0; i < secretLength; i++)
            stringBuilder.Append(_characters.GetRandom());
        return stringBuilder.ToString();
    }

    /// <summary>Returns the current character pool as a string.</summary>
    public override string ToString() => string.Concat(_characters);
}
