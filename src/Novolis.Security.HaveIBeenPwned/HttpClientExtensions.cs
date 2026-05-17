using Microsoft.Extensions.Options;

namespace Novolis.Security.HaveIBeenPwned;

internal static class HttpClientExtensions
{
    public static void Configure(this HttpClient httpClient, IOptions<HibpConfiguration> options)
    {
        httpClient.BaseAddress = options.Value.BaseAddress;
        httpClient.DefaultRequestHeaders.Add("hibp-api-key", options.Value.ApiKey);
        httpClient.DefaultRequestHeaders.Add("user-agent", options.Value.ApplicationName);
    }
}