using Microsoft.Extensions.Logging;

namespace Novolis.Security.OAuth;

/// <summary>Default OAuth event sink. Writes identifiers only to <see cref="ILogger{TCategoryName}"/>.</summary>
public sealed class LoggerEventStore(ILogger<LoggerEventStore> logger) : IEventStore
{
    /// <inheritdoc />
    public ValueTask RecordAsync(SecurityEvent evt, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(evt);
        if (string.IsNullOrEmpty(evt.Error))
        {
            logger.LogInformation(
                "OAuth {Type} client={ClientId} identity={IdentityId} grant={GrantType}",
                evt.Type,
                evt.ClientId,
                evt.IdentityId,
                evt.GrantType);
        }
        else
        {
            logger.LogWarning(
                "OAuth {Type} client={ClientId} identity={IdentityId} grant={GrantType} error={Error}",
                evt.Type,
                evt.ClientId,
                evt.IdentityId,
                evt.GrantType,
                evt.Error);
        }

        return ValueTask.CompletedTask;
    }
}
