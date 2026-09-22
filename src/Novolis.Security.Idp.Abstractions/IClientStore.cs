namespace Novolis.Security.Idp;

/// <summary>Looks up OAuth clients by public <c>client_id</c>.</summary>
public interface IClientStore
{
    /// <summary>Finds a client by exact <paramref name="clientId"/>.</summary>
    ValueTask<IdpClient?> FindByClientIdAsync(string clientId, CancellationToken ct = default);

    /// <summary>Inserts or replaces a client.</summary>
    ValueTask UpsertAsync(IdpClient client, CancellationToken ct = default);
}
