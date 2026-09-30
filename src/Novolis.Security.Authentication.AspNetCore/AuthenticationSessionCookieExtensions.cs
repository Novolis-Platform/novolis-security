using Microsoft.AspNetCore.Http;
using Novolis.Security.OAuth.AspNetCore;

namespace Novolis.Security.Authentication.AspNetCore;

/// <summary>Browser session-cookie helpers for the OAuth authorization endpoint.</summary>
public static class AuthenticationSessionCookieExtensions
{
    /// <summary>Writes the authentication session cookie used by <c>/oauth/authorize</c>.</summary>
    public static void AppendNovolisAuthenticationSession(
        this HttpResponse response,
        string sessionId,
        DateTimeOffset expiresUtc)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentException.ThrowIfNullOrEmpty(sessionId);
        response.Cookies.Append(
            OAuthEndpointRouteBuilderExtensions.AuthenticationSessionCookie,
            sessionId,
            new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Expires = expiresUtc,
            });
    }

    /// <summary>Deletes the authentication session cookie.</summary>
    public static void DeleteNovolisAuthenticationSession(this HttpResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        response.Cookies.Delete(OAuthEndpointRouteBuilderExtensions.AuthenticationSessionCookie);
    }
}
