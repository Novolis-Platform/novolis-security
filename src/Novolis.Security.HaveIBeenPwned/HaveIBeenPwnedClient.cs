using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Novolis.Security.HaveIBeenPwned;

public class HaveIBeenPwnedClient(IHttpClientFactory clientFactory, ILogger<HaveIBeenPwnedClient> logger, IOptions<HibpConfiguration> options) : IHaveIBeenPwnedClient
{
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

    public async Task<IEnumerable<PasswordDetails>> GetPasswordDetailsAsync(string password) => await GetPasswordDetailsAsync(new Sha1Hash(password));
    
    private async Task<IEnumerable<PasswordDetails>> GetPasswordDetailsAsync(Sha1Hash hash)
    {
        using var client = clientFactory.CreateClient();
        var response = await client.GetStringAsync($"{options.Value.PwnedPasswordAddress}/{hash.Prefix}");
        logger.LogInformation("Response: {Response}", response);
        var parsedResponse = ParseResponse(response);
        return parsedResponse.Select(pair => CreatePassword(pair, hash.Prefix));
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