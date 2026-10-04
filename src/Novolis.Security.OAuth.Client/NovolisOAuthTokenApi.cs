using Novolis.Http.Client;

namespace Novolis.Security.OAuth.Client;

/// <summary>Private named client used only for discovery, token, and revocation calls.</summary>
internal sealed class NovolisOAuthTokenApi() : HttpClientKey;
