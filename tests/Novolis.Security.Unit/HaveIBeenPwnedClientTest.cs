using Novolis.Security.HaveIBeenPwned;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TUnit.Core;

namespace Novolis.Security.Tests;

public class HaveIBeenPwnedClientTest
{
    private readonly IServiceProvider _services = BuildServices();

    private static IServiceProvider BuildServices()
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.Debug));
        services.AddNovolisPwnedPasswordsClient();
        services.AddSingleton<IHaveIBeenPwnedClient, HaveIBeenPwnedClient>();
        return services.BuildServiceProvider();
    }

    [Test]
    public async Task AddNovolisPwnedPasswordsClient_pins_the_range_origin()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddNovolisPwnedPasswordsClient();
        await using var provider = services.BuildServiceProvider();
        var client = provider.GetRequiredService<IHttpClientFactory>().CreateClient(PwnedPasswordsApi.HttpClientName);
        await Assert.That(client.BaseAddress!.Scheme).IsEqualTo("https");
        await Assert.That(client.BaseAddress.Host).IsEqualTo(HaveIBeenPwnedClient.AllowedPwnedPasswordsHost);
        await Assert.That(client.DefaultRequestHeaders.Contains("Add-Padding")).IsTrue();
    }

    [Test]
    [Skip("Integration test — requires network")]
    public async Task CheckPassword_PwnedPassword_ReturnsTrue()
    {
        var client = _services.GetRequiredService<IHaveIBeenPwnedClient>();
        await Assert.That(await client.IsPwnedAsync("password")).IsTrue();
    }
}
