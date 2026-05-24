namespace Novolis.Security.Secrets;

/// <summary>Convenience overloads for <see cref="SecretGenerator"/>.</summary>
public static class SecretGeneratorExtensions
{
    /// <summary>Generates a charset secret with the given length.</summary>
    public static string GenerateCharsetSecret(this SecretGenerator generator, int length)
        => generator.GenerateCharsetSecret(new SecretGeneratorOptions { Length = length });

    /// <summary>Generates a charset secret with explicit character classes.</summary>
    public static string GenerateCharsetSecret(
        this SecretGenerator generator,
        int length,
        bool includeUppercase,
        bool includeLowercase,
        bool includeDigits,
        bool includeSpecial,
        bool includeHomoglyphs,
        bool includeWhitespace)
        => generator.GenerateCharsetSecret(new SecretGeneratorOptions
        {
            Length = length,
            IncludeUppercase = includeUppercase,
            IncludeLowercase = includeLowercase,
            IncludeDigits = includeDigits,
            IncludeSpecial = includeSpecial,
            IncludeHomoglyphs = includeHomoglyphs,
            IncludeWhitespace = includeWhitespace
        });

    /// <summary>Generates a word passphrase with the given word count.</summary>
    public static string GenerateWordPassphrase(this SecretGenerator generator, int wordCount)
        => generator.GenerateWordPassphrase(new PassphraseOptions { WordCount = wordCount });
}
