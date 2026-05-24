using Novolis.Security.Secrets.Internals;
using Novolis.Security.WordLists;

namespace Novolis.Security.Secrets;

/// <summary>Builds a random word passphrase from included word lists.</summary>
public class PassphraseBuilder(int wordCount)
{
    private readonly List<string> _words = [];
    private uint _shuffleCount;

    /// <summary>Adds the noun word list.</summary>
    public PassphraseBuilder IncludeNouns()
    {
        _words.AddRange(Nouns.Get());
        return this;
    }

    /// <summary>Adds the adjective word list.</summary>
    public PassphraseBuilder IncludeAdjectives()
    {
        _words.AddRange(Adjectives.Get());
        return this;
    }

    /// <summary>Adds the verb word list.</summary>
    public PassphraseBuilder IncludeVerbs()
    {
        _words.AddRange(Verbs.Get());
        return this;
    }

    /// <summary>Adds the adverb word list.</summary>
    public PassphraseBuilder IncludeAdverbs()
    {
        _words.AddRange(Adverbs.Get());
        return this;
    }

    /// <summary>Adds the country name list.</summary>
    public PassphraseBuilder IncludeCountries()
    {
        _words.AddRange(Countries.Get());
        return this;
    }

    /// <summary>Adds the culture name list.</summary>
    public PassphraseBuilder IncludeCultures()
    {
        _words.AddRange(Cultures.Get());
        return this;
    }

    /// <summary>Adds the color name list.</summary>
    public PassphraseBuilder IncludeColorNames()
    {
        _words.AddRange(ColorNames.Get());
        return this;
    }

    /// <summary>Shuffles the combined word pool before sampling.</summary>
    public PassphraseBuilder Shuffle(uint shuffleCount = 1)
    {
        _shuffleCount = shuffleCount;
        return this;
    }

    /// <summary>Builds the final passphrase string.</summary>
    public string Build()
    {
        if (_words.Count == 0)
            throw new InvalidOperationException("No word lists were included. Call Include* methods before Build().");

        var passphrase = new List<string>();
        _words.Shuffle(_shuffleCount);
        for (var index = 0; index < wordCount; index++)
            passphrase.Add(_words.GetRandom());
        return string.Join(" ", passphrase);
    }
}
