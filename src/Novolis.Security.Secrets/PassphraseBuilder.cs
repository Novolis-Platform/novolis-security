using Novolis.Security.Secrets.Internals;
using Novolis.Security.WordLists;

namespace Novolis.Security.Secrets;

public class PassphraseBuilder(int wordCount)
{
    private readonly List<string> _words = [];
    private uint _shuffleCount;

    public PassphraseBuilder IncludeNouns()
    {
        _words.AddRange(Nouns.Get());
        return this;
    }

    public PassphraseBuilder IncludeAdjectives()
    {
        _words.AddRange(Adjectives.Get());
        return this;
    }

    public PassphraseBuilder IncludeVerbs()
    {
        _words.AddRange(Verbs.Get());
        return this;
    }

    public PassphraseBuilder IncludeAdverbs()
    {
        _words.AddRange(Adverbs.Get());
        return this;
    }

    public PassphraseBuilder IncludeCountries()
    {
        _words.AddRange(Countries.Get());
        return this;
    }

    public PassphraseBuilder IncludeCultures()
    {
        _words.AddRange(Cultures.Get());
        return this;
    }

    public PassphraseBuilder IncludeColorNames()
    {
        _words.AddRange(ColorNames.Get());
        return this;
    }

    public PassphraseBuilder Shuffle(uint shuffleCount = 1)
    {
        _shuffleCount = shuffleCount;
        return this;
    }

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
