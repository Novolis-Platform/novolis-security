using System.Security.Claims;
using Novolis.Security.Authentication;

namespace Novolis.Security.Authorization.AspNetCore;

/// <summary>Reads the global identity from a validated access token.</summary>
public static class ClaimsIdentityExtensions
{
    /// <summary>Parses JWT <c>sub</c> as <see cref="IdentityId"/>.</summary>
    public static IdentityId? GetNovolisIdentityId(this ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        var subject = principal.FindFirstValue("sub") ?? principal.FindFirstValue(ClaimTypes.NameIdentifier);
        return IdentityId.TryParse(subject, out var identityId) ? identityId : null;
    }
}
