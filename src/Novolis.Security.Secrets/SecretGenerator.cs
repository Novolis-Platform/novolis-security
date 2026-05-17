namespace Novolis.Security.Secrets;

public class SecretGenerator : ISecretGenerator
{
    public string GenerateCharsetSecret(SecretGeneratorOptions? options = null)
        => SecretBuilder.GenerateFromSettings(options ?? new SecretGeneratorOptions());

    public string GenerateWordPassphrase(PassphraseOptions? options = null)
    {
        options ??= new PassphraseOptions();
        var builder = new PassphraseBuilder(options.WordCount);
        if (options.IncludeNouns)
            builder.IncludeNouns();
        if (options.IncludeAdjectives)
            builder.IncludeAdjectives();
        if (options.IncludeVerbs)
            builder.IncludeVerbs();
        if (options.IncludeAdverbs)
            builder.IncludeAdverbs();
        if (options.IncludeCountries)
            builder.IncludeCountries();
        if (options.IncludeCultures)
            builder.IncludeCultures();
        if (options.IncludeColorNames)
            builder.IncludeColorNames();
        builder.Shuffle();
        return builder.Build();
    }
}
