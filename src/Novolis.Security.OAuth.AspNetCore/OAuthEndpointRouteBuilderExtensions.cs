using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Novolis.Security.Authentication;
using Novolis.Security.OAuth;

namespace Novolis.Security.OAuth.AspNetCore;

/// <summary>Maps the standards-oriented OAuth authorization-server endpoints.</summary>
public static class OAuthEndpointRouteBuilderExtensions
{
    /// <summary>Cookie name carrying the browser authentication session used by <c>/oauth/authorize</c>.</summary>
    public const string AuthenticationSessionCookie = "Novolis.Authentication.Session";

    static readonly JsonSerializerOptions TokenJson = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Maps Authorization Code, token, revocation, discovery, and JWKS endpoints.</summary>
    public static IEndpointRouteBuilder MapNovolisOAuth(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints.MapGet("/oauth/authorize", AuthorizeAsync);
        endpoints.MapPost("/oauth/token", IssueTokenAsync).DisableAntiforgery();
        endpoints.MapPost("/oauth/revoke", RevokeTokenAsync).DisableAntiforgery();
        endpoints.MapGet("/.well-known/oauth-authorization-server", Discovery);
        endpoints.MapGet("/.well-known/jwks.json", Jwks);

        var options = endpoints.ServiceProvider.GetService<IOptions<OAuthOptions>>();
        if (options?.Value.EnableOpenIdConfigurationAlias == true)
            endpoints.MapGet("/.well-known/openid-configuration", Discovery);

        return endpoints;
    }

    static async Task<IResult> AuthorizeAsync(
        HttpContext context,
        IClientStore clients,
        ITokenService tokens,
        CancellationToken cancellationToken)
    {
        var request = context.Request.Query;
        var responseType = request["response_type"].ToString();
        var clientId = request["client_id"].ToString();
        var redirectUri = request["redirect_uri"].ToString();
        var state = request["state"].ToString();
        var client = await clients.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);

        if (client is null || client.Disabled)
            return OAuthError(context, OAuthTokenErrors.InvalidClient);
        if (!string.Equals(responseType, "code", StringComparison.Ordinal))
            return OAuthError(context, OAuthTokenErrors.InvalidRequest);
        if (!client.AllowedGrantTypes.Contains(OAuthGrantTypes.AuthorizationCode, StringComparer.Ordinal))
            return OAuthError(context, OAuthTokenErrors.UnauthorizedClient);
        if (!client.AllowedRedirectUris.Contains(redirectUri, StringComparer.Ordinal))
            return OAuthError(context, OAuthTokenErrors.InvalidRequest);

        var challenge = request["code_challenge"].ToString();
        var method = request["code_challenge_method"].ToString();
        if (string.IsNullOrWhiteSpace(challenge)
            || !string.Equals(method, "S256", StringComparison.Ordinal))
            return RedirectOrError(context, redirectUri, state, OAuthTokenErrors.InvalidRequest);

        var authentication = context.RequestServices.GetService<IAuthenticationService>();
        var sessionId = context.Request.Cookies[AuthenticationSessionCookie];
        var identityId = authentication is null
            ? null
            : await authentication.GetAuthenticatedIdentityAsync(sessionId ?? "", cancellationToken)
                .ConfigureAwait(false);
        if (identityId is null)
            return RedirectOrError(context, redirectUri, state, OAuthTokenErrors.AccessDenied);

        var issued = await tokens.IssueAuthorizationCodeAsync(
            new AuthorizationCodeIssueRequest
            {
                ClientId = clientId,
                RedirectUri = redirectUri,
                IdentityId = identityId.Value,
                Scope = request["scope"].ToString(),
                Audience = request["audience"].ToString(),
                CodeChallenge = challenge,
                CodeChallengeMethod = method,
            },
            cancellationToken).ConfigureAwait(false);
        if (!issued.Succeeded || issued.Code is null)
            return RedirectOrError(context, redirectUri, state, issued.Error ?? OAuthTokenErrors.InvalidRequest);

        var location = QueryHelpers.AddQueryString(
            redirectUri,
            new Dictionary<string, string?>
            {
                ["code"] = issued.Code,
                ["state"] = string.IsNullOrWhiteSpace(state) ? null : state,
            });
        return Results.Redirect(location, permanent: false, preserveMethod: false);
    }

    static async Task<IResult> IssueTokenAsync(
        HttpContext context,
        ITokenService tokens,
        CancellationToken cancellationToken)
    {
        ApplyNoStore(context);
        if (!IsUrlEncodedForm(context) || !await TryReadFormAsync(context, cancellationToken).ConfigureAwait(false))
            return TokenError(context, OAuthTokenErrors.InvalidRequest);

        var form = context.Request.Form;
        if (!TryResolveClient(context, form, out var clientId, out var clientSecret, out var clientError))
            return clientError!;

        var result = await tokens.IssueAsync(
            new TokenIssueRequest
            {
                GrantType = form["grant_type"].ToString(),
                ClientId = clientId,
                ClientSecret = clientSecret,
                AuthorizationCode = form["code"].ToString(),
                RedirectUri = form["redirect_uri"].ToString(),
                CodeVerifier = form["code_verifier"].ToString(),
                RefreshToken = form["refresh_token"].ToString(),
                Scope = form["scope"].ToString(),
                Audience = form["audience"].ToString(),
            },
            cancellationToken).ConfigureAwait(false);

        if (!result.Succeeded)
            return TokenError(context, result.Error ?? OAuthTokenErrors.InvalidRequest, result.ErrorDescription);

        return Results.Json(
            new
            {
                access_token = result.AccessToken,
                token_type = result.TokenType,
                expires_in = result.ExpiresIn,
                refresh_token = result.RefreshToken,
                scope = result.Scope,
            },
            TokenJson);
    }

    static async Task<IResult> RevokeTokenAsync(
        HttpContext context,
        ITokenService tokens,
        CancellationToken cancellationToken)
    {
        ApplyNoStore(context);
        if (!IsUrlEncodedForm(context) || !await TryReadFormAsync(context, cancellationToken).ConfigureAwait(false))
            return TokenError(context, OAuthTokenErrors.InvalidRequest);

        var form = context.Request.Form;
        if (!TryResolveClient(context, form, out var clientId, out var clientSecret, out var clientError))
            return clientError!;

        var accepted = await tokens.RevokeAsync(
            form["token"].ToString(),
            clientId,
            clientSecret,
            form["token_type_hint"].ToString(),
            cancellationToken).ConfigureAwait(false);
        return accepted ? Results.Ok() : TokenError(context, OAuthTokenErrors.InvalidClient);
    }

    static IResult Jwks(OAuthTokenService tokens) =>
        Results.Json(ToPublicJwks(tokens.GetJsonWebKeySet()), TokenJson);

    static IResult Discovery(IOptions<OAuthOptions> options)
    {
        var issuer = options.Value.Issuer.ToString().TrimEnd('/');
        return Results.Json(
            new
            {
                issuer,
                authorization_endpoint = $"{issuer}/oauth/authorize",
                token_endpoint = $"{issuer}/oauth/token",
                revocation_endpoint = $"{issuer}/oauth/revoke",
                jwks_uri = $"{issuer}/.well-known/jwks.json",
                grant_types_supported = new[]
                {
                    OAuthGrantTypes.AuthorizationCode,
                    OAuthGrantTypes.ClientCredentials,
                    OAuthGrantTypes.RefreshToken,
                },
                response_types_supported = new[] { "code" },
                code_challenge_methods_supported = new[] { "S256" },
                token_endpoint_auth_methods_supported = new[] { "client_secret_post", "client_secret_basic" },
            },
            TokenJson);
    }

    static object ToPublicJwks(Microsoft.IdentityModel.Tokens.JsonWebKeySet set) => new
    {
        keys = set.Keys.Select(k => new
        {
            kty = k.Kty,
            use = "sig",
            kid = k.Kid,
            crv = k.Crv,
            x = k.X,
            y = k.Y,
            alg = k.Alg,
        }),
    };

    static bool TryResolveClient(
        HttpContext context,
        IFormCollection form,
        out string? clientId,
        out string? clientSecret,
        out IResult? error)
    {
        clientId = null;
        clientSecret = null;
        error = null;
        TryReadClientFromBasic(context, out var basicId, out var basicSecret);
        var formId = form["client_id"].ToString();
        var formSecret = form["client_secret"].ToString();

        if (basicId is not null)
        {
            if (!string.IsNullOrEmpty(formId) && !string.Equals(formId, basicId, StringComparison.Ordinal))
            {
                error = TokenError(context, OAuthTokenErrors.InvalidClient);
                return false;
            }

            clientId = basicId;
            clientSecret = basicSecret;
            return true;
        }

        clientId = formId;
        clientSecret = string.IsNullOrEmpty(formSecret) ? null : formSecret;
        return true;
    }

    static void TryReadClientFromBasic(
        HttpContext context,
        out string? clientId,
        out string? clientSecret)
    {
        clientId = null;
        clientSecret = null;
        if (!AuthenticationHeaderValue.TryParse(context.Request.Headers.Authorization, out var header)
            || !string.Equals(header.Scheme, "Basic", StringComparison.OrdinalIgnoreCase)
            || header.Parameter is null)
            return;

        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(header.Parameter));
            var split = decoded.IndexOf(':');
            if (split <= 0)
                return;
            clientId = decoded[..split];
            clientSecret = decoded[(split + 1)..];
        }
        catch (FormatException)
        {
            // Missing credentials are handled as invalid_client by the token service.
        }
    }

    static async Task<bool> TryReadFormAsync(HttpContext context, CancellationToken cancellationToken)
    {
        try
        {
            _ = await context.Request.ReadFormAsync(cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (InvalidDataException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    static bool IsUrlEncodedForm(HttpContext context) =>
        context.Request.ContentType is { } contentType
        && contentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase);

    static IResult RedirectOrError(
        HttpContext context,
        string redirectUri,
        string? state,
        string error)
    {
        if (string.IsNullOrWhiteSpace(redirectUri))
            return OAuthError(context, error);

        var location = QueryHelpers.AddQueryString(
            redirectUri,
            new Dictionary<string, string?>
            {
                ["error"] = error,
                ["state"] = string.IsNullOrWhiteSpace(state) ? null : state,
            });
        return Results.Redirect(location, permanent: false, preserveMethod: false);
    }

    static IResult OAuthError(HttpContext context, string error, string? description = null)
    {
        ApplyNoStore(context);
        return Results.Json(new { error, error_description = description }, TokenJson, statusCode: StatusCodes.Status400BadRequest);
    }

    static IResult TokenError(HttpContext context, string error, string? description = null)
    {
        ApplyNoStore(context);
        var status = error switch
        {
            OAuthTokenErrors.InvalidClient => StatusCodes.Status401Unauthorized,
            OAuthTokenErrors.RateLimited => StatusCodes.Status429TooManyRequests,
            _ => StatusCodes.Status400BadRequest,
        };
        if (status == StatusCodes.Status401Unauthorized)
            context.Response.Headers.WWWAuthenticate = "Basic realm=\"oauth\"";

        return Results.Json(new { error, error_description = description }, TokenJson, statusCode: status);
    }

    static void ApplyNoStore(HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";
    }
}