using System.Security.Claims;

namespace Novolis.Security.Authentication.Entra;

/// <summary>
/// Host-provided gate that maps an Entra principal onto a product session.
/// Return false (or throw) to reject principals that are not already admitted users.
/// </summary>
public interface INovolisEntraPrincipalAdmission
{
    /// <summary>
    /// Creates or refreshes the application principal for <paramref name="entraPrincipal"/>.
    /// Returning null rejects the sign-in without throwing.
    /// </summary>
    Task<ClaimsPrincipal?> AdmitAsync(
        ClaimsPrincipal entraPrincipal,
        CancellationToken cancellationToken = default);
}
