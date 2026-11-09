using Novolis.Security.Authentication.Entra;

namespace Novolis.Security.Unit;

public sealed class EntraSignInReturnUrlTests
{
    [Test]
    public async Task ResolveReturnUrl_AllowsRelativePaths()
    {
        var options = CreateOptions();
        var redirect = NovolisEntraSignInEndpointRouteBuilderExtensions.ResolveReturnUrl(
            "/month",
            options);

        await Assert.That(redirect).IsEqualTo("/month");
    }

    [Test]
    public async Task ResolveReturnUrl_AllowsAllowlistedOrigins()
    {
        var options = CreateOptions();
        var redirect = NovolisEntraSignInEndpointRouteBuilderExtensions.ResolveReturnUrl(
            "https://hours.example/month",
            options);

        await Assert.That(redirect).IsEqualTo("https://hours.example/month");
    }

    [Test]
    public async Task ResolveReturnUrl_RejectsForeignOrigins()
    {
        var options = CreateOptions();
        var redirect = NovolisEntraSignInEndpointRouteBuilderExtensions.ResolveReturnUrl(
            "https://evil.example/",
            options);

        await Assert.That(redirect).IsEqualTo("/");
    }

    private static NovolisEntraSignInOptions CreateOptions()
    {
        var options = new NovolisEntraSignInOptions { DefaultReturnPath = "/" };
        options.AllowedReturnOrigins.Add("https://hours.example");
        return options;
    }
}
