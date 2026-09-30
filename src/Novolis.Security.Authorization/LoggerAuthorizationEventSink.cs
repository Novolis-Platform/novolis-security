using Microsoft.Extensions.Logging;

namespace Novolis.Security.Authorization;

/// <summary>Default authorization event sink. Writes identifiers only to <see cref="ILogger{TCategoryName}"/>.</summary>
public sealed class LoggerAuthorizationEventSink(ILogger<LoggerAuthorizationEventSink> logger)
    : IAuthorizationEventSink
{
    /// <inheritdoc />
    public ValueTask RecordAsync(
        AuthorizationSecurityEvent securityEvent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        logger.LogWarning(
            "Authorization {Type} tenant={TenantId} identity={IdentityId} permission={PermissionId}",
            securityEvent.Type,
            securityEvent.TenantId,
            securityEvent.IdentityId,
            securityEvent.PermissionId);
        return ValueTask.CompletedTask;
    }
}
