using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Novolis.Security.Authentication.Entra;

/// <summary>Registers Microsoft Entra OpenID Connect interactive sign-in.</summary>
public static class NovolisEntraSignInServiceCollectionExtensions
{
    /// <summary>
    /// Adds an OpenID Connect scheme that challenges Microsoft Entra and, after token validation,
    /// replaces the temporary Entra principal with the host admission result.
    /// </summary>
    public static AuthenticationBuilder AddNovolisEntraSignIn(
        this AuthenticationBuilder authentication,
        Action<NovolisEntraSignInOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(authentication);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new NovolisEntraSignInOptions();
        configure(options);
        if (!options.IsConfigured)
        {
            throw new InvalidOperationException(
                "Novolis Entra sign-in requires TenantId, ClientId, ClientSecret, and callback/challenge paths.");
        }

        authentication.Services.AddSingleton(options);
        authentication.AddOpenIdConnect(
            options.OpenIdConnectScheme,
            openIdConnect =>
            {
                openIdConnect.Authority =
                    $"https://login.microsoftonline.com/{options.TenantId}/v2.0";
                openIdConnect.ClientId = options.ClientId;
                openIdConnect.ClientSecret = options.ClientSecret;
                openIdConnect.CallbackPath = options.CallbackPath;
                openIdConnect.SignInScheme = options.SignInScheme;
                openIdConnect.ResponseType = OpenIdConnectResponseType.Code;
                openIdConnect.SaveTokens = false;
                openIdConnect.MapInboundClaims = false;
                openIdConnect.Scope.Clear();
                openIdConnect.Scope.Add("openid");
                openIdConnect.Scope.Add("profile");
                openIdConnect.Scope.Add("email");
                openIdConnect.TokenValidationParameters.NameClaimType = "name";
                openIdConnect.TokenValidationParameters.ValidateIssuer = false;
                openIdConnect.Events.OnTokenValidated = async context =>
                {
                    var admission = context.HttpContext.RequestServices
                        .GetRequiredService<INovolisEntraPrincipalAdmission>();
                    var admitted = await admission
                        .AdmitAsync(context.Principal!, context.HttpContext.RequestAborted)
                        .ConfigureAwait(false);
                    if (admitted?.Identity?.IsAuthenticated != true)
                    {
                        context.Fail(
                            "The Microsoft account is not linked to an admitted product user.");
                        return;
                    }

                    context.Principal = admitted;
                };
                openIdConnect.Events.OnRemoteFailure = context =>
                {
                    context.Response.Redirect(
                        $"{options.DefaultReturnPath.TrimEnd('/')}?microsoftSignIn=failed");
                    context.HandleResponse();
                    return Task.CompletedTask;
                };
            });

        return authentication;
    }
}
