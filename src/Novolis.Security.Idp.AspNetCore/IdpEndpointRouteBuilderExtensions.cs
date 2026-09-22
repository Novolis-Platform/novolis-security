using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using Novolis.Security.Idp;

namespace Novolis.Security.Idp.AspNetCore;

/// <summary>Maps token, revoke, JWKS, and discovery endpoints.</summary>
public static class IdpEndpointRouteBuilderExtensions
{
    static readonly JsonSerializerOptions TokenJson = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>
    /// Maps <c>/oauth/token</c>, <c>/oauth/revoke</c>, <c>/.well-known/jwks.json</c>,
    /// and <c>/.well-known/openid-configuration</c>.
    /// </summary>
    /// <remarks>
    /// Password grant form field <c>username</c> is the opaque <see cref="AccountId"/> GUID.
    /// Do not send email or a login name — those are resolved in a different system.
    /// </remarks>
    public static IEndpointRouteBuilder MapNovolisIdp(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints.MapPost("/oauth/token", IssueTokenAsync)
            .RequireRateLimiting(IdpAspNetCoreServiceCollectionExtensions.TokenRateLimitPolicy)
            .DisableAntiforgery();
        endpoints.MapPost("/oauth/revoke", RevokeTokenAsync).DisableAntiforgery();
        endpoints.MapGet("/.well-known/jwks.json", Jwks);
        endpoints.MapGet("/.well-known/openid-configuration", Discovery);
        return endpoints;
    }

    static async Task<IResult> IssueTokenAsync(HttpContext context, IIdpTokenService tokens, CancellationToken ct)
    {
        ApplyNoStore(context);
        if (!IsUrlEncodedForm(context))
            return TokenError(context, IdpTokenErrors.InvalidRequest);

        if (!await TryReadFormAsync(context, ct).ConfigureAwait(false))
            return TokenError(context, IdpTokenErrors.InvalidRequest);

        var form = context.Request.Form;
        if (!TryResolveClient(context, form, out var clientId, out var clientSecret, out var clientError))
            return clientError!;

        var username = form["username"].ToString();
        AccountId? accountId = null;
        if (!string.IsNullOrWhiteSpace(username))
        {
            if (!TryParseAccountId(username, out var guid) || guid == Guid.Empty)
                return TokenError(context, IdpTokenErrors.InvalidGrant);
            accountId = new AccountId(guid);
        }

        var result = await tokens.IssueAsync(
            new TokenIssueRequest
            {
                GrantType = form["grant_type"].ToString(),
                ClientId = clientId,
                ClientSecret = clientSecret,
                AccountId = accountId,
                Password = form["password"].ToString(),
                RefreshToken = form["refresh_token"].ToString(),
                Scope = form["scope"].ToString(),
            },
            ct).ConfigureAwait(false);

        if (!result.Succeeded)
            return TokenError(context, result.Error ?? IdpTokenErrors.InvalidRequest, result.ErrorDescription);

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

    static async Task<IResult> RevokeTokenAsync(HttpContext context, IIdpTokenService tokens, CancellationToken ct)
    {
        ApplyNoStore(context);
        if (!IsUrlEncodedForm(context))
            return TokenError(context, IdpTokenErrors.InvalidRequest);

        if (!await TryReadFormAsync(context, ct).ConfigureAwait(false))
            return TokenError(context, IdpTokenErrors.InvalidRequest);

        var form = context.Request.Form;
        if (!TryResolveClient(context, form, out var clientId, out var clientSecret, out var clientError))
            return clientError!;

        var token = form["token"].ToString();
        if (string.IsNullOrWhiteSpace(token))
            token = form["refresh_token"].ToString();

        var authenticated = await tokens.RevokeRefreshTokenAsync(token, clientId, clientSecret, ct).ConfigureAwait(false);
        if (!authenticated)
            return TokenError(context, IdpTokenErrors.InvalidClient);

        return Results.Ok();
    }

    static IResult Jwks(IdpTokenService tokens) => Results.Json(ToPublicJwks(tokens.GetJsonWebKeySet()));

    static IResult Discovery(IOptions<IdpOptions> options)
    {
        var issuer = options.Value.Issuer.TrimEnd('/');
        return Results.Json(new
        {
            issuer,
            token_endpoint = $"{issuer}/oauth/token",
            revocation_endpoint = $"{issuer}/oauth/revoke",
            jwks_uri = $"{issuer}/.well-known/jwks.json",
            grant_types_supported = new[]
            {
                IdpGrantTypes.ClientCredentials,
                IdpGrantTypes.Password,
                IdpGrantTypes.RefreshToken,
            },
            token_endpoint_auth_methods_supported = new[] { "client_secret_post", "client_secret_basic" },
            id_token_signing_alg_values_supported = new[] { "ES384" },
            response_types_supported = new[] { "token" },
            authorization_endpoint = (string?)null,
        }, TokenJson);
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
                error = TokenError(context, IdpTokenErrors.InvalidClient);
                return false;
            }

            clientId = basicId;
            clientSecret = basicSecret;
            return true;
        }

        clientId = formId;
        clientSecret = formSecret;
        return true;
    }

    static void TryReadClientFromBasic(HttpContext context, out string? clientId, out string? clientSecret)
    {
        clientId = null;
        clientSecret = null;
        if (!AuthenticationHeaderValue.TryParse(context.Request.Headers.Authorization, out var header))
            return;
        if (!string.Equals(header.Scheme, "Basic", StringComparison.OrdinalIgnoreCase) || header.Parameter is null)
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
            // Treat as missing client credentials; IssueAsync returns invalid_client.
        }
    }

    static async Task<bool> TryReadFormAsync(HttpContext context, CancellationToken ct)
    {
        try
        {
            _ = await context.Request.ReadFormAsync(ct).ConfigureAwait(false);
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

    static bool IsUrlEncodedForm(HttpContext context)
    {
        var contentType = context.Request.ContentType;
        return contentType is not null
               && contentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase);
    }

    static bool TryParseAccountId(string username, out Guid guid)
    {
        if (Guid.TryParseExact(username, "D", out guid))
            return true;
        return Guid.TryParseExact(username, "N", out guid);
    }

    static IResult TokenError(HttpContext context, string error, string? description = null)
    {
        ApplyNoStore(context);
        var status = error == IdpTokenErrors.InvalidClient
            ? StatusCodes.Status401Unauthorized
            : StatusCodes.Status400BadRequest;
        if (status == StatusCodes.Status401Unauthorized)
            context.Response.Headers.WWWAuthenticate = "Basic realm=\"idp\"";

        return Results.Json(new { error, error_description = description }, TokenJson, statusCode: status);
    }

    static void ApplyNoStore(HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";
    }
}
