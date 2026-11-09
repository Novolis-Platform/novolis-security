using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Novolis.Security.Authentication.Entra;

/// <summary>Maps the Microsoft Entra challenge endpoint.</summary>
public static class NovolisEntraSignInEndpointRouteBuilderExtensions
{
    /// <summary>Challenges the configured Entra OpenID Connect scheme and returns to a local or allowlisted origin.</summary>
    public static IEndpointConventionBuilder MapNovolisEntraSignIn(
        this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var options = endpoints.ServiceProvider.GetRequiredService<NovolisEntraSignInOptions>();
        return endpoints.MapGet(options.ChallengePath, (string? returnUrl) =>
        {
            var redirect = ResolveReturnUrl(returnUrl, options);
            return Results.Challenge(
                new AuthenticationProperties { RedirectUri = redirect },
                [options.OpenIdConnectScheme]);
        }).AllowAnonymous();
    }

    internal static string ResolveReturnUrl(string? returnUrl, NovolisEntraSignInOptions options)
    {
        if (string.IsNullOrWhiteSpace(returnUrl))
        {
            return options.DefaultReturnPath;
        }

        if (returnUrl.StartsWith("/", StringComparison.Ordinal) &&
            !returnUrl.StartsWith("//", StringComparison.Ordinal))
        {
            return returnUrl;
        }

        if (Uri.TryCreate(returnUrl, UriKind.Absolute, out var absolute) &&
            options.AllowedReturnOrigins.Any(origin =>
                Uri.TryCreate(origin, UriKind.Absolute, out var allowed) &&
                string.Equals(absolute.GetLeftPart(UriPartial.Authority),
                    allowed.GetLeftPart(UriPartial.Authority),
                    StringComparison.OrdinalIgnoreCase)))
        {
            return absolute.ToString();
        }

        return options.DefaultReturnPath;
    }
}
