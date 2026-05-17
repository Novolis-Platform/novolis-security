using System.Text;
using Novolis.Security.Cryptography.Internals;
using Novolis.Security.Resources;

namespace Novolis.Security.Cryptography;

public class PasswordBuilder(int passwordLength)
{
    private readonly List<char> _characters = new();
    private uint _shuffleCount = 0;

    /// <summary>
    /// Generates a password based on the given password options.
    /// </summary>
    /// <param name="options">The password generator options.</param>
    /// <returns>A randomly generated password that adheres to the provided options.</returns>
    public static string GenerateFromSettings(PasswordGeneratorOptions options)
    {
        var passwordBuilder = new PasswordBuilder(options.Length);
        if (options.IncludeUppercase)
            passwordBuilder.IncludeUppercase();
        if (options.IncludeLowercase)
            passwordBuilder.IncludeLowercase();
        if (options.IncludeDigits)
            passwordBuilder.IncludeDigits();
        if (options.IncludeSpecial)
            passwordBuilder.IncludeSpecial();
        if (options.IncludeHomoglyphs)
            passwordBuilder.IncludeHomoglyphs();
        if (options.IncludeWhitespace)
            passwordBuilder.IncludeWhitespace();
        passwordBuilder.Shuffle();
        return passwordBuilder.Build();
    }   
    
    /// <summary>
    /// Includes uppercase characters in the password.
    /// </summary>
    /// <returns>The updated PasswordBuilder instance with uppercase letters included.</returns>
    public PasswordBuilder IncludeUppercase()
    {
        _characters.AddRange(Characters.Uppercase.Except(Characters.Homoglyphs));
        return this;
    }

    /// <summary>
    /// Adds lowercase letters to the list of characters used to build a password.
    /// </summary>
    /// <returns>The updated PasswordBuilder instance with lowercase letters included.</returns>
    public PasswordBuilder IncludeLowercase()
    {
        _characters.AddRange(Characters.Lowercase.Except(Characters.Homoglyphs));
        return this;
    }

    /// <summary>
    /// Includes digits in the password builder.
    /// </summary>
    /// <returns>A PasswordBuilder object with digits included.</returns>
    public PasswordBuilder IncludeDigits()
    {
        _characters.AddRange(Characters.Digits.Except(Characters.Homoglyphs));
        return this;
    }

    /// <summary>
    /// Includes special characters in the password.
    /// </summary>
    /// <returns>A PasswordBuilder object with special characters included.</returns>
    public PasswordBuilder IncludeSpecial()
    {
        _characters.AddRange(Characters.Special.Except(Characters.Homoglyphs));
        return this;
    }

    /// <summary>
    /// Includes homoglyphs in the password.
    /// </summary>
    /// <returns>
    /// The PasswordBuilder instance with the added homoglyphs.
    /// </returns>
    public PasswordBuilder IncludeHomoglyphs()
    {
        _characters.AddRange(Characters.Homoglyphs);
        return this;
    }

    /// <summary>
    /// Appends whitespace characters to the character list.
    /// </summary>
    /// <returns>A reference to the PasswordBuilder instance.</returns>
    public PasswordBuilder IncludeWhitespace()
    {
        _characters.AddRange(Characters.Whitespace);
        return this;
    }

    /// <summary>
    /// Resets the PasswordBuilder instance by clearing the characters list and the string builder.
    /// </summary>
    /// <returns>The updated PasswordBuilder instance.</returns>
    public PasswordBuilder Reset()
    {
        _characters.Clear();
        return this;
    }

    /// <summary>
    /// Shuffles the characters of the password. This is done by swapping the characters at random positions.
    /// </summary>
    /// <remarks>The shuffle is done multiple times to ensure a more random result using a random number.</remarks>
    /// <returns>The PasswordBuilder instance.</returns>
    public PasswordBuilder Shuffle(uint shuffleCount = 1)
    {
        _shuffleCount = shuffleCount;
        return this;
    }

    /// <summary>
    /// Builds a random password based on the specified password length and characters.
    /// </summary>
    /// <returns>The generated password as a string.</returns>
    public string Build()
    {
        var stringBuilder = new StringBuilder();
        _characters.Shuffle(_shuffleCount);
        for (var i = 0; i < passwordLength; i++) stringBuilder.Append(_characters.GetRandom());
        return stringBuilder.ToString().ReplaceLineEndings(_characters.GetRandom().ToString());
    }

    /// <summary>
    /// Helper method to get an idea of what the state of the password builder is.
    /// </summary>
    /// <returns>a string that contains all the characters in the current instance, that is used to generate passwords from.</returns>
    public override string ToString() => string.Concat(_characters);
}