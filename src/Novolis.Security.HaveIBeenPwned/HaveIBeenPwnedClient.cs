using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Novolis.Security.HaveIBeenPwned;

/// <summary>Default <see cref="IHaveIBeenPwnedClient"/> using the k-anonymity range API.</summary>
public class HaveIBeenPwnedClient(IHttpClientFactory clientFactory, ILogger<HaveIBeenPwnedClient> logger, IOptions<HibpConfiguration> options) : IHaveIBeenPwnedClient
{
    /// <summary>Host that must be used for Pwned Passwords range lookups.</summary>
    public const string AllowedPwnedPasswordsHost = "api.pwnedpasswords.com";
    /// <inheritdoc />
    public async Task<bool> IsPwnedAsync(string password, uint threshold = 0)
    {
        var hash = new Sha1Hash(password);
        var passwordDetails = await GetPasswordDetailsAsync(hash);
        passwordDetails = passwordDetails.ToArray();
        if (!passwordDetails.Any()) return false;
        var passwordDetail = passwordDetails.FirstOrDefault(details => details.Sha1Suffix == hash.Suffix);
        
        if (passwordDetail == null) return false;

        if (passwordDetail.TimesPwned == 0)
            return false;
        
        if (threshold < passwordDetail.TimesPwned)
            return true;
        
        return false;
    }

    /// <inheritdoc />
    public async Task<IEnumerable<PasswordDetails>> GetPasswordDetailsAsync(string password) => await GetPasswordDetailsAsync(new Sha1Hash(password));
    
    private async Task<IEnumerable<PasswordDetails>> GetPasswordDetailsAsync(Sha1Hash hash)
    {
        EnsurePinnedRangeOrigin(options.Value.PwnedPasswordAddress);
        using var client = clientFactory.CreateClient();
        var response = await client.GetStringAsync($"{options.Value.PwnedPasswordAddress}/{hash.Prefix}");
        var parsedResponse = ParseResponse(response).ToArray();
        logger.LogDebug("Pwned Passwords range lookup completed with {SuffixCount} suffixes.", parsedResponse.Length);
        return parsedResponse.Select(pair => CreatePassword(pair, hash.Prefix));
    }

    static void EnsurePinnedRangeOrigin(Uri address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (!string.Equals(address.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(address.Host, AllowedPwnedPasswordsHost, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Pwned Passwords requests must use https://" + AllowedPwnedPasswordsHost + ".");
        }
    }

    private static PasswordDetails CreatePassword(KeyValuePair<string, uint?> pair, string prefix)
    {
        var output = new PasswordDetails
        {
            Sha1Hash = string.Concat(prefix, pair.Key),
            Sha1Prefix = prefix,
            Sha1Suffix = pair.Key,
            TimesPwned = pair.Value ?? 0,
        };
        return output;
    }

    private static IEnumerable<KeyValuePair<string, uint?>> ParseResponse(string content) 
        => content.Split(Environment.NewLine).Select(line => line.Split(':')).Select(split => new KeyValuePair<string, uint?>(split[0], uint.Parse(split[1])));
}