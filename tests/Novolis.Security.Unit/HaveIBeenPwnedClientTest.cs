using Novolis.Security.HaveIBeenPwned;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Novolis.Testing.Logging;
using TUnit.Core;

namespace Novolis.Security.Tests;

public class HaveIBeenPwnedClientTest
{
    private readonly IServiceProvider _services = BuildServices();

    private static IServiceProvider BuildServices()
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.Debug));
        services.AddHttpClient();
        services.Configure<HibpConfiguration>(o => o.PwnedPasswordAddress = new Uri("https://api.pwnedpasswords.com/range"));
        services.AddSingleton<IHaveIBeenPwnedClient, HaveIBeenPwnedClient>();
        return services.BuildServiceProvider();
    }

    [Test]
    [Skip("Integration test — requires network")]
    public async Task CheckPassword_PwnedPassword_ReturnsTrue()
    {
        var client = _services.GetRequiredService<IHaveIBeenPwnedClient>();
        await Assert.That(await client.IsPwnedAsync("password")).IsTrue();
    }
}
