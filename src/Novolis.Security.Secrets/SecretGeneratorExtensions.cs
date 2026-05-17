namespace Novolis.Security.Secrets;

public static class SecretGeneratorExtensions
{
    public static string GenerateCharsetSecret(this SecretGenerator generator, int length)
        => generator.GenerateCharsetSecret(new SecretGeneratorOptions { Length = length });

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

    public static string GenerateWordPassphrase(this SecretGenerator generator, int wordCount)
        => generator.GenerateWordPassphrase(new PassphraseOptions { WordCount = wordCount });
}
