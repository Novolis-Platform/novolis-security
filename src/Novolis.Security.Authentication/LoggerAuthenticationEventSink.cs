using Microsoft.Extensions.Logging;

namespace Novolis.Security.Authentication;

/// <summary>Default authentication event sink. Writes identifiers only to <see cref="ILogger{TCategoryName}"/>.</summary>
public sealed class LoggerAuthenticationEventSink(ILogger<LoggerAuthenticationEventSink> logger)
    : IAuthenticationEventSink
{
    /// <inheritdoc />
    public ValueTask RecordAsync(
        AuthenticationSecurityEvent securityEvent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        if (string.IsNullOrEmpty(securityEvent.Error))
        {
            logger.LogInformation(
                "Authentication {Type} identity={IdentityId}",
                securityEvent.Type,
                securityEvent.IdentityId);
        }
        else
        {
            logger.LogWarning(
                "Authentication {Type} identity={IdentityId} error={Error}",
                securityEvent.Type,
                securityEvent.IdentityId,
                securityEvent.Error);
        }

        return ValueTask.CompletedTask;
    }
}
