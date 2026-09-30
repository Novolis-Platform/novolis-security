# Novolis Security: Authentication, OAuth and Authorization

## 1. Purpose

Novolis Security provides a small, self-hosted **token mint** and **tenant authorization framework** for applications that need more than ad-hoc login but do **not** need a full enterprise Identity Provider.

It is **not** Duende IdentityServer, Keycloak, Auth0, or Entra. There is no OpenID Connect login protocol, no userinfo, no IdP federation, and no admin or consent UI. Positioning: [docs/what-this-is.md](docs/what-this-is.md).

The primary target is a family of first-party applications such as:

- games and launchers
- companion applications
- account portals
- administration tools
- small APIs
- hobby applications
- nano-SaaS products
- internal tools

The system should make the common path extremely easy while retaining recognizable, standards-based behavior underneath.

A developer should be able to start with:

```csharp
builder.Services
    .AddNovolisAuthentication()
    .AddNovolisAuthorization();
```

without first becoming an OAuth specialist.

At the same time, another developer inspecting the protocol surface should find OAuth, JWT, PKCE, JWKS, scopes, audiences and revocation rather than a proprietary authentication protocol.

The core philosophy is:

> Standards-first at protocol boundaries, strongly typed and opinionated at developer boundaries.

---

# 2. Architectural principles

## 2.1 Authentication and authorization are separate systems

Authentication answers:

> Who is this identity, and has that identity been authenticated?

Authorization answers:

> May this authenticated identity perform this operation within this tenant and resource context?

Neither subsystem owns the other's state.

Authentication may produce facts useful to authorization, such as the authenticated `IdentityId`, client, audience and scopes.

Authentication does not own groups, roles, permissions or tenant membership.

Authorization does not know passwords, credentials, login identifiers, OAuth sessions, refresh tokens or signing keys.

---

## 2.2 Identity is global

An identity belongs to the person or principal, not to an application or tenant.

For example:

```text
Identity: 2f5c...

├── Space Game
├── Farming Simulator
├── Account Portal
└── Administration Tool
```

The same identity can authenticate to all of them.

The applications do not create separate copies of that identity merely because their authorization relationships differ.

The JWT `sub` represents this global identity.

---

## 2.3 Authorization is tenant-scoped

An identity's relationship with one tenant has no implicit effect on another tenant.

For example:

```text
Identity 2f5c...

Space Game
    Moderator
    Player

Farming Simulator
    Player
    Beta Tester
```

Being a moderator in Space Game does not imply anything in Farming Simulator.

Every authorization decision therefore includes a `TenantId`.

An API such as this is valid:

```csharp
AuthorizeAsync(
    identityId,
    tenantId,
    permission);
```

An API such as this should not exist:

```csharp
IsModerator(identityId);
```

because it permits accidental cross-tenant authorization.

---

# 3. Package structure

The intended high-level package family is:

```text
Novolis.Security.Authentication.Abstractions
Novolis.Security.Authentication
Novolis.Security.Authentication.AspNetCore
Novolis.Security.Authentication.Storage

Novolis.Security.OAuth.Abstractions
Novolis.Security.OAuth
Novolis.Security.OAuth.AspNetCore
Novolis.Security.OAuth.Storage

Novolis.Security.Authorization.Abstractions
Novolis.Security.Authorization
Novolis.Security.Authorization.AspNetCore
Novolis.Security.Authorization.Storage
```

`Authorization.Storage` should only exist if concrete storage adapters warrant a separate package. The abstractions must not require it.

Existing lower-level packages such as cryptography, password hashing, encryption, secure text and secrets remain independent.

---

# 4. Dependency direction

The intended dependency graph is:

```text
Authentication
      │
      ├──────────────► PasswordHashing / Cryptography
      │
      ▼
    OAuth
      │
      ▼
Cryptographic primitives


Authorization
      │
      ▼
Authentication.Abstractions
    only where IdentityId integration is required
```

Authorization must not depend on the OAuth implementation.

OAuth must not depend on Authorization.

The high-level Authentication package may compose OAuth, credential verification and application-facing authentication behavior.

---

# 5. High-level Authentication package

`Novolis.Security.Authentication` is the preferred entry point for normal applications.

It exists to hide protocol ceremony, not to replace standards.

Its responsibilities include:

- identity resolution
- credential verification
- account lifecycle abstractions
- authentication session establishment
- composition of OAuth services
- convenient ASP.NET Core integration
- sensible security defaults
- optional registration and password-management workflows

A normal application should not need to manually construct token requests.

Conceptually:

```csharp
var result = await authentication.SignInAsync(
    identifier,
    password,
    cancellationToken);
```

may result internally in an OAuth-compatible authorization flow without leaking all of that machinery into application code.

Advanced consumers may use the lower-level OAuth packages directly.

---

# 6. Credential-store isolation

The credential vault is not a user directory.

This is a non-negotiable security boundary.

## Identity storage may contain

```text
IdentityId
Email
Username
DisplayName
CredentialReference
Profile information
Application-neutral identity metadata
```

## Credential storage may contain

```text
internal database key
CredentialReference
PasswordHash
Disabled
CreatedUtc
UpdatedUtc
credential-specific security state
```

Credential storage must not contain:

```text
IdentityId
email
username
phone
display name
hashes of those identifiers
tenant relationships
authorization data
```

The credential reference exists solely to locate credential material indirectly.

It is not an identity.

It must never become:

- JWT `sub`
- a public account identifier
- an API route identifier
- a tenant membership identifier
- a foreign key exposed across the application model

A suitable type is:

```csharp
public readonly record struct CredentialReference(Guid Value)
{
    public static CredentialReference New()
        => new(Guid.NewGuid());
}
```

The reference must be cryptographically opaque and must not use time-ordered GUID generation.

Internal database primary keys may use database-appropriate identifiers independently of `CredentialReference`.

---

# 7. Identity model

The public authentication identity is represented by:

```csharp
public readonly record struct IdentityId(Guid Value);
```

`IdentityId` is stable across applications using the same authentication authority.

It is suitable for use as the OAuth/JWT subject.

It does not reveal login identifiers or credential information.

An identity may exist without membership in any tenant.

This is important for cases such as:

- newly registered users
- users who have left all products
- account-level settings
- account recovery
- future product enrollment

---

# 8. OAuth subsystem

`Novolis.Security.OAuth` provides the standards-oriented protocol layer.

It must be usable independently of the high-level Authentication façade.

The initial supported grants are:

```text
Authorization Code + PKCE
Client Credentials
Refresh Token
```

The Resource Owner Password Credentials grant is not supported.

RFC 9700 states that the password grant must not be used, and requires authorization servers to support PKCE.

For native applications such as launchers and games, authorization should use an external user agent and PKCE rather than collecting the user's password inside the client. This follows the OAuth native-application best current practice.

---

# 9. OAuth endpoints

The standard protocol surface should include:

```text
GET  /oauth/authorize
POST /oauth/token
POST /oauth/revoke

GET  /.well-known/oauth-authorization-server
GET  /.well-known/jwks.json
```

Exact route prefixes may be configurable, but the defaults should remain conventional.

Authorization-server metadata follows RFC 8414. Its canonical discovery endpoint is:

```text
/.well-known/oauth-authorization-server
```

RFC 8414 defines this metadata as the mechanism through which clients discover authorization-server endpoints and capabilities.

An `openid-configuration` alias may be added for compatibility if needed, but the library must not claim OpenID Connect capabilities it does not implement.

---

# 10. OpenID Connect

OpenID Connect is not required for the initial scope.

The library must not expose OIDC-specific claims or metadata such as:

```text
id_token
userinfo_endpoint
nonce semantics
OIDC response types
```

unless the corresponding OIDC behavior is genuinely implemented.

An optional future package may provide:

```text
Novolis.Security.OpenIdConnect
```

on top of the OAuth and Authentication foundations.

OAuth access tokens must not be casually rebranded as ID tokens.

---

# 11. Authorization Code and PKCE

Authorization Code is the primary interactive flow.

PKCE is mandatory.

Only secure code challenge mechanisms are supported, with `S256` as the baseline.

RFC 7636 specifically recommends S256 over `plain`, and RFC 9700 requires authorization servers to support PKCE and enforce the verifier when a challenge was supplied.

Authorization codes must be:

- short-lived
- single-use
- client-bound
- redirect-URI-bound
- PKCE-bound
- atomically consumed

Reusing a consumed authorization code must fail.

---

# 12. Clients

OAuth clients are independent from identities.

A client represents an application participating in OAuth.

Examples include:

```text
space-game-launcher
space-game-web
space-game-admin
farm-simulator-client
farm-simulator-web
```

A client definition includes at minimum:

```csharp
ClientId
ClientType
AllowedGrantTypes
AllowedRedirectUris
AllowedScopes
AllowedAudiences
Disabled
```

Confidential clients may additionally have credentials.

Public clients must never rely on an embedded static client secret for security.

---

# 13. Access tokens

Access tokens are JWTs.

The preferred signing algorithm remains:

```text
ES384
```

unless a deliberate future compatibility requirement introduces additional algorithms.

Validation must explicitly allow only configured algorithms.

Algorithm negotiation must never silently accept:

```text
none
HS*
RS*
ES256
```

when the issuer is configured for ES384.

JWT access tokens should follow the interoperability principles of RFC 9068. RFC 9068 defines a standard JWT profile specifically for OAuth access tokens.

A typical access token contains:

```json
{
  "iss": "https://accounts.example.com",
  "sub": "2f5c...",
  "aud": "space-game-api",
  "client_id": "space-game-launcher",
  "scope": "game profile",
  "iat": 1790630000,
  "nbf": 1790630000,
  "exp": 1790630900,
  "jti": "..."
}
```

The credential reference must never appear in the token.

---

# 14. Audience isolation

Access tokens should normally be restricted to one resource server or a deliberately small resource set.

RFC 9700 recommends audience-restricted access tokens to reduce the effect of token leakage.

Therefore:

```text
Space Game token
    aud = space-game-api
```

must not automatically authorize:

```text
Farming Simulator API
```

even though both applications share the same identity authority.

SSO shares authentication.

It does not share credentials indiscriminately.

---

# 15. Refresh tokens

Refresh tokens are opaque bearer credentials.

They are not JWTs.

Each refresh token contains sufficient cryptographic entropy generated from a CSPRNG.

Only a cryptographic hash of the secret is persisted.

A refresh token is bound to at least:

```text
client
identity
authorization grant/family
approved scope
approved audience
expiry
```

Refresh tokens rotate on every successful use.

RFC 9700 requires public clients to use sender-constrained refresh tokens or refresh-token rotation. The initial Novolis implementation uses rotation.

---

# 16. Refresh-token replay detection

Rotation must be storage-atomic.

The storage abstraction must expose something equivalent to:

```csharp
ValueTask<RefreshRotationResult> TryRotateAsync(
    RefreshTokenId current,
    RefreshTokenRecord replacement,
    CancellationToken cancellationToken);
```

The contract is:

> Replace the current refresh token only if it remains active and unused.

Two concurrent requests using the same refresh token must never both succeed.

This guarantee belongs to durable storage.

A distributed cache or lease may improve contention handling but must not be the only correctness mechanism.

On detected reuse, the token family should be considered compromised and revoked according to configured policy.

---

# 17. Revocation

The OAuth layer provides token revocation compatible with RFC 7009.

RFC 7009 defines an authorization-server revocation endpoint and requires support for revoking refresh tokens.

Revocation should support:

```text
individual refresh token
refresh-token family
client authorization grant
identity session where appropriate
```

Short-lived JWT access tokens may normally expire naturally.

Immediate access-token invalidation requires an explicit strategy and should not accidentally turn every API request into a central database lookup.

---

# 18. Signing-key lifecycle

The signing-key system is a real key ring.

At any time there is:

```text
one current signing key
zero or more validation-only historical keys
```

When rotating:

```text
K1 signs tokens

K2 becomes current

K1 remains published and valid for verification
until every K1-signed access token can no longer be valid
```

Historical keys must remain in JWKS for at least:

```text
maximum access-token lifetime
+ allowed clock skew
```

after their final possible issuance.

`kid` values must be stable.

Loading the same configured key after restart must not randomly produce a different `kid`.

An explicit configured `kid` or deterministic key thumbprint is preferred.

---

# 19. Authentication sessions and SSO

The authorization server may maintain a browser authentication session independently from OAuth access tokens.

This provides SSO.

For example:

```text
User signs into accounts.example.com

        ↓

Space Game /authorize
        ↓
authorization code
        ↓
Space Game token

        ↓ later

Farming Simulator /authorize
        ↓
existing authentication session recognized
        ↓
new authorization code
        ↓
Farming Simulator token
```

The identity is shared.

The tokens are not.

The authorization relationships are not.

---

# 20. Authorization subsystem

`Novolis.Security.Authorization` owns application authorization.

Its central rule is:

> Groups contain identities. Roles contain permissions. Composite roles contain roles.

All assignments are evaluated within a tenant.

The core concepts are:

```csharp
public readonly record struct TenantId(Guid Value);
public readonly record struct GroupId(Guid Value);
public readonly record struct RoleId(string Value);
public readonly record struct PermissionId(string Value);
```

`IdentityId` is shared from Authentication abstractions.

---

# 21. Tenant

A tenant is an authorization partition.

It does not necessarily correspond to a customer organization.

Examples include:

```text
Space Game
Farming Simulator
Acme Corporation
Community Server 42
Tournament Environment
```

The framework does not assume what a tenant means.

An application with only one authorization domain may simply configure one tenant.

This allows simple applications to remain simple without making the underlying authorization model single-tenant.

---

# 22. Groups

A group is a named set of identities.

Conceptually:

```text
Group
    = IdentityId[]
```

Groups do not contain permissions.

Groups do not define authorization policy.

Groups exist to make assignment convenient.

Example:

```text
Moderators
    Alice
    Frank
    Sarah
```

A minimal definition is:

```csharp
public sealed record Group(
    GroupId Id,
    TenantId TenantId,
    string Name);
```

Membership is separate:

```csharp
public sealed record GroupMembership(
    TenantId TenantId,
    GroupId GroupId,
    IdentityId IdentityId);
```

Nested groups are not part of the initial design.

---

# 23. Permissions

A permission is the smallest named application capability.

Examples:

```text
player.view
player.kick
player.ban
chat.mute
economy.view
economy.adjust
server.restart
```

Permissions are normally defined in application code because application code gives them meaning.

They have stable string values for persistence and transport.

The preferred strongly typed contract is:

```csharp
public interface IPermission
{
    static abstract string Value { get; }
}
```

Example:

```csharp
public static class Permissions
{
    public static class Moderator
    {
        public static class Player
        {
            public sealed class Kick : IPermission
            {
                public static string Value
                    => "moderator.player.kick";
            }

            public sealed class Ban : IPermission
            {
                public static string Value
                    => "moderator.player.ban";
            }
        }
    }
}
```

The type is the compile-time API.

The string is the stable runtime identity.

---

# 24. Roles

A role is a named set of permissions.

Conceptually:

```text
Role
    = Permission[]
```

Example:

```text
Moderator

    moderator.player.kick
    moderator.player.ban
    chat.mute
```

A role may be:

```text
code-backed
store-backed
```

The authorization engine must not care where the definition originated.

---

# 25. Code-backed roles

Applications may define roles in code.

A suitable abstraction is:

```csharp
public interface IRole
{
    static abstract string Value { get; }
}
```

A built-in role can additionally expose its permission definition:

```csharp
public interface IBuiltInRole : IRole
{
    static abstract IReadOnlySet<PermissionId> Permissions { get; }
}
```

For example:

```csharp
public sealed class Moderator : IBuiltInRole
{
    public static string Value => "moderator";

    public static IReadOnlySet<PermissionId> Permissions { get; }
        = new HashSet<PermissionId>
        {
            new("moderator.player.kick"),
            new("moderator.player.ban"),
            new("chat.mute")
        };
}
```

Built-in role definitions are immutable at runtime.

Their assignments are not.

---

# 26. Store-backed custom roles

A tenant may define custom roles using the known permission catalog.

Example:

```text
Tournament Marshal

    tournament.start
    tournament.pause
    moderator.player.kick
    player.teleport
```

No code change is required.

A custom role definition belongs to its tenant.

Deleting or changing a custom role must affect future authorization evaluation after appropriate cache invalidation.

Unknown permission identifiers must not silently become valid merely because they were inserted into storage.

---

# 27. Composite roles

Authorization does not implement role inheritance.

Instead it implements explicit composition.

Conceptually:

```text
CompositeRole
    = Role[]
```

Example:

```text
SeniorModerator

    Moderator
    SupportAgent
    EconomyManager
```

This does not imply:

```text
SeniorModerator IS-A Moderator
```

It states:

```text
SeniorModerator contains Moderator
```

Composition describes authorization structure more accurately than inheritance.

---

# 28. Composite-role graph

Composite roles may contain normal roles or other composite roles.

The resulting graph must be acyclic.

This is valid:

```text
Administrator
    Operations
    Economy

Operations
    Moderator
    Support
```

This is invalid:

```text
A → B
B → C
C → A
```

Cycles must be rejected at mutation time where possible and detected defensively during evaluation.

Composite-role expansion produces the union of the permissions from every reachable role.

---

# 29. Role assignments

Roles may be assigned directly to an identity:

```text
Identity → Role
```

or to a group:

```text
Group → Role
```

Both assignments are tenant-scoped.

Example:

```text
Tenant: Space Game

Frank → BetaTester

Moderators group → Moderator
Admins group → Administrator
```

A user's effective role set is:

```text
direct role assignments
∪
roles assigned to groups containing the identity
```

Composite roles are then recursively expanded.

---

# 30. Effective permissions

Effective permissions are the union of all permissions reachable through the identity's role assignments.

Conceptually:

```text
Identity
   │
   ├── direct role assignments
   │
   └── groups
          │
          └── role assignments
                 │
                 └── composite expansion
                         │
                         └── permissions
```

Equivalent set expression:

```text
EffectivePermissions =
    DirectRolePermissions
    ∪ GroupRolePermissions
    ∪ CompositeRolePermissions
```

Duplicates have no semantic effect.

The result is a set.

---

# 31. No implicit deny rules

Version 1 uses positive permissions with default deny.

If an identity has a permission, access may be granted.

If it does not, access is denied.

There is no initial concept of:

```text
negative permission
deny role
deny overrides allow
```

Those features introduce ordering and policy-resolution complexity and should only be introduced in response to a real requirement.

---

# 32. Direct permission assignments

Version 1 should not require direct identity-to-permission assignments.

The primary model is:

```text
Identity/Group → Role → Permission
```

Even a one-off capability can be represented by a small custom role.

This improves auditability and keeps one assignment model.

Direct permission grants may be added later if a genuine use case justifies them.

---

# 33. Permissions versus roles in application code

Application operations should normally require permissions.

For example:

```csharp
[RequirePermission<Permissions.Moderator.Player.Kick>]
public Task KickPlayer(...)
```

This means:

> The caller must possess the capability to kick a player.

It does not care whether that permission came from:

```text
Moderator
SeniorModerator
TournamentMarshal
a tenant-defined custom role
a group assignment
a direct role assignment
```

This preserves abstraction.

Role checks remain available when the role itself is semantically important.

```csharp
[RequireRole<Roles.Moderator>]
```

means:

> The caller must actually have the Moderator role.

These are intentionally different semantics.

---

# 34. Generic ASP.NET Core authorization metadata

Modern generic attributes allow strongly typed authorization declarations.

The preferred controller API is:

```csharp
[RequirePermission<Permissions.Moderator.Player.Kick>]
```

and:

```csharp
[RequireRole<Roles.Moderator>]
```

The equivalent minimal API syntax is:

```csharp
app.MapPost("/players/{id}/kick", KickPlayer)
    .RequirePermission<Permissions.Moderator.Player.Kick>();
```

and:

```csharp
app.MapGet("/moderation", GetModeration)
    .RequireRole<Roles.Moderator>();
```

There should be no normal reason to type:

```csharp
"moderator.player.kick"
```

inside application endpoint code.

---

# 35. Attributes are metadata only

Generic attributes must not contain authorization logic.

For example:

```csharp
public sealed class RequirePermissionAttribute<TPermission>
    : Attribute
    where TPermission : IPermission
{
}
```

exists to describe a requirement.

ASP.NET integration translates this metadata into the core authorization system.

The core authorization engine remains independent of:

```text
HttpContext
ControllerBase
Endpoint
Attribute
ASP.NET Core
```

This allows the same engine to be used from:

- ASP.NET Core
- SignalR
- game servers
- background services
- desktop applications
- administration tools
- tests

---

# 36. Programmatic authorization

Resource-aware authorization must be available without attributes.

Example:

```csharp
var result = await authorization.AuthorizeAsync(
    identityId,
    tenantId,
    Permissions.Moderator.Player.Kick,
    cancellationToken);
```

For domain-resource evaluation:

```csharp
var result = await authorization.AuthorizeAsync(
    identityId,
    tenantId,
    player,
    PlayerActions.Kick,
    cancellationToken);
```

The second form allows application-specific policy handlers to combine permission checks with resource-specific rules.

For example:

```text
has player.kick
AND target is not protected
AND target belongs to current tenant
```

The framework must not attempt to encode every possible domain rule into roles.

---

# 37. Role providers

Role definitions are obtained through provider abstractions rather than assuming SQL or compiled code.

Conceptually:

```csharp
public interface IRoleProvider
{
    ValueTask<RoleDefinition?> FindAsync(
        TenantId tenantId,
        RoleId roleId,
        CancellationToken cancellationToken);
}
```

Implementations may include:

```text
BuiltInRoleProvider
StoredRoleProvider
CompositeRoleProvider
```

A composition layer presents them as one logical role catalog.

Provider precedence must be deterministic.

A tenant-defined role must not silently override a protected built-in role unless explicitly supported.

---

# 38. Permission catalog

Applications register the permissions they understand.

Conceptually:

```csharp
services.AddPermission<Permissions.Moderator.Player.Kick>();
services.AddPermission<Permissions.Moderator.Player.Ban>();
```

Convenience registration may scan an assembly or use generated registration, but correctness must not depend on fragile runtime magic.

The catalog provides:

```text
stable permission ID
display metadata where configured
description where configured
declaring application/module
```

The authorization core only requires the stable ID.

UI-friendly metadata is optional.

---

# 39. Strongly typed helpers

The framework should provide conversions such as:

```csharp
PermissionId Permission<TPermission>()
    where TPermission : IPermission;
```

and:

```csharp
RoleId Role<TRole>()
    where TRole : IRole;
```

so generic static members remain confined to the developer-facing type system.

Internal authorization processing operates on small value types such as:

```csharp
PermissionId
RoleId
TenantId
IdentityId
```

---

# 40. Storage abstractions

Storage contracts describe capabilities rather than database technology.

The authorization subsystem needs abstractions approximately equivalent to:

```text
IGroupStore
IGroupMembershipStore
IRoleStore
IRoleAssignmentStore
```

OAuth requires dedicated stores for concepts where atomicity matters:

```text
IAuthorizationCodeStore
IRefreshTokenStore
ISigningKeyStore
IClientStore
```

A generic repository abstraction must not be used when it cannot express the required consistency guarantee.

In particular:

```text
consume-once authorization code
refresh-token rotation
revocation races
```

must have dedicated atomic operations.

---

# 41. Storage implementations

Supported stores may include:

```text
In-memory
SQLite
SQL Server
PostgreSQL
JSON/file storage for development where safe
custom consumer implementations
```

An implementation must not claim to support a feature if it cannot uphold that feature's concurrency contract.

SQLite tests should use real in-memory SQLite rather than replacing database semantics with a fake repository.

---

# 42. Caching

Effective authorization is highly cacheable.

A suitable cache key is conceptually:

```text
TenantId + IdentityId + AuthorizationVersion
```

or an equivalent dependency-aware key.

Changes requiring invalidation include:

```text
group membership changed
role assignment changed
custom role changed
composite role changed
permission composition changed
tenant membership removed
```

Correctness must not depend on eventually noticing a stale authorization relationship for an unbounded period.

Short-lived caches or explicit versioning are preferable.

---

# 43. Tenant context

Authorization never guesses the tenant from an identity.

Tenant context must be explicit or deterministically established by the application.

Possible sources include:

```text
route
host
authenticated application context
resource identifier
explicit service argument
```

The authorization framework should expose an abstraction such as:

```csharp
ITenantContextAccessor
```

for ASP.NET convenience.

The core engine still receives a concrete `TenantId`.

---

# 44. Tenant and token relationship

JWTs do not need to contain every tenant membership.

The preferred generic access token is:

```json
{
  "sub": "2f5c...",
  "aud": "space-game-api",
  "scope": "game profile"
}
```

The Space Game API obtains its own tenant context and asks Authorization about:

```text
Identity 2f5c...
Tenant SpaceGame
```

This avoids:

- leaking unrelated tenant memberships
- very large JWTs
- stale role lists
- stale group relationships
- coupling authentication to authorization storage

For deployments where stateless tenant-specific claims are deliberately useful, current-tenant authorization claims may be emitted as an optimization, but they are not the canonical source of authorization truth.

---

# 45. OAuth scopes versus permissions

OAuth scopes and application permissions are deliberately different.

Scopes describe what an OAuth client/session has been authorized to request from a resource server.

Examples:

```text
game
profile
inventory
moderation
```

Permissions describe what an identity may actually do inside the application.

Examples:

```text
player.kick
player.ban
economy.adjust
```

Therefore:

```text
scope=moderation
```

does not by itself mean:

```text
player.kick = allowed
```

A request may require both:

```text
OAuth scope permits use of moderation API
AND
Authorization grants player.kick in this tenant
```

This prevents scopes from gradually becoming the entire application's authorization database.

---

# 46. Default ASP.NET Core composition

A simple application should be able to configure:

```csharp
builder.Services
    .AddNovolisAuthentication(options =>
    {
        options.Issuer = new Uri("https://accounts.example.com");
    })
    .AddNovolisAuthorization();
```

The high-level extension composes appropriate lower-level services.

An advanced application can instead configure:

```csharp
builder.Services.AddNovolisOAuth(...);
builder.Services.AddNovolisAuthorization(...);
```

directly.

The easy API is a façade over the same implementation, not a separate authentication system.

---

# 47. Resource-server composition

An API that only consumes Novolis-issued tokens should have a minimal setup.

Conceptually:

```csharp
builder.Services
    .AddAuthentication()
    .AddNovolisBearer(
        issuer: "https://accounts.example.com",
        audience: "space-game-api");
```

The integration should support metadata and JWKS discovery rather than requiring consumers to manually copy signing keys.

Issuer, audience, signature, algorithm and lifetime validation are mandatory.

---

# 48. Simple application experience

A small game should not need to care about:

```text
signing-key serialization
token-family persistence
PKCE implementation details
JWT handler configuration
refresh-token hashing
JWKS generation
OAuth metadata shape
authorization policy plumbing
```

Those are library responsibilities.

The application should mostly care about:

```text
Who can register?
How are users identified?
Which OAuth clients exist?
Which audiences exist?
Which permissions exist?
Which roles should users receive?
Which tenant is this request for?
```

---

# 49. Security defaults

Secure behavior is the default behavior.

Unsafe behavior should require explicit opt-in where it is supported at all.

Defaults include:

```text
HTTPS required outside development
PKCE S256 required
short-lived access tokens
rotating refresh tokens
refresh reuse detection
audience validation
issuer validation
algorithm allowlisting
strong signing keys
credential-store isolation
constant-time secret comparison
password hashing through Novolis password hashing
no password grant
no plaintext refresh-token persistence
no wildcard redirect URIs
exact redirect URI validation
default deny authorization
```

---

# 50. Time

All time-dependent behavior uses `TimeProvider`.

No core or storage implementation should directly call:

```csharp
DateTimeOffset.UtcNow
DateTime.UtcNow
```

This applies to:

```text
token expiry
authorization-code expiry
refresh-token expiry
signing-key validity
rate-limit windows
credential timestamps
authorization cache expiry
security events
```

This makes behavior deterministic and testable without weakening production fidelity.

---

# 51. IDs and randomness

Different identifiers have different requirements.

Externally visible or security-sensitive correlation identifiers should be opaque and non-predictable.

Examples:

```text
CredentialReference
authorization code secret
refresh-token secret
security nonce
```

must use CSPRNG-backed randomness.

Internal database identifiers with no secrecy requirement may use GUID v7 or database-generated keys when beneficial.

A security-sensitive identifier must never use time ordering merely because it is convenient for an index.

---

# 52. Secrets

Raw secrets should exist in memory for the shortest practical period.

Where byte-oriented APIs allow it, secret buffers should be zeroed after use.

Persisted forms should normally contain:

```text
identifier
salt/hash or secret hash
metadata
```

rather than the original secret.

Logging must never contain:

```text
password
authorization code
refresh token
client secret
private signing key
```

---

# 53. Events and auditing

Authentication and authorization should expose structured security events.

Examples include:

```text
SignInSucceeded
SignInFailed
CredentialDisabled
AuthorizationCodeIssued
AuthorizationCodeRedeemed
RefreshTokenRotated
RefreshTokenReuseDetected
TokenRevoked
ClientAuthenticationFailed
AuthorizationDenied
RoleAssigned
RoleRemoved
GroupMembershipChanged
CustomRoleChanged
CompositeRoleChanged
```

Event delivery failure must not accidentally convert successful security operations into inconsistent state.

Critical security-state changes should be persisted transactionally where appropriate rather than relying exclusively on best-effort telemetry.

---

# 54. Testing strategy

Tests should exercise the system as close to production behavior as practical.

Database tests use in-memory SQLite or the real provider being tested.

Mocks are reserved for genuine external boundaries where an in-memory implementation is inappropriate.

Core security tests should be adversarial.

Required categories include:

```text
JWT algorithm confusion
unsigned token rejection
wrong issuer
wrong audience
expired token
future token
tampered token
unknown signing key
signing-key rollover
JWKS private material leakage

authorization-code replay
PKCE mismatch
PKCE downgrade
redirect URI mismatch
client mismatch

refresh-token replay
concurrent refresh
family revocation
expired refresh token
scope escalation
audience escalation
client mismatch

credential timing behavior
disabled credentials
invalid credential references
credential-store PII invariant

cross-tenant authorization
group membership changes
role assignment changes
composite-role cycles
custom-role changes
permission cache invalidation
unknown permissions

role versus permission semantics
direct versus group role assignment
composite expansion
default deny
```

Concurrency tests must prove that exactly one competing refresh or authorization-code redemption can succeed.

---

# 55. Authorization test invariant

A particularly important invariant is:

> Authorization for Tenant A must never be influenced by assignments belonging solely to Tenant B.

This should be tested repeatedly across:

```text
direct roles
groups
custom roles
composite roles
cached effective permissions
resource-aware authorization
```

Multi-tenancy bugs should be treated as security bugs.

---

# 56. Credential isolation test invariant

Automated architecture/security tests should assert that credential-domain records do not acquire identity fields over time.

The credential assembly or models should reject or flag concepts such as:

```text
Email
Username
Phone
DisplayName
IdentityId
TenantId
GroupId
RoleId
```

This protects the boundary from gradual convenience-driven erosion.

---

# 57. Non-goals

The initial stack is not intended to provide:

```text
SAML
SCIM
enterprise federation
social login aggregation
FAPI
complex consent management
dynamic client registration
full OpenID Provider behavior
arbitrary policy-language execution
ABAC rule engines
nested groups
negative authorization rules
enterprise directory synchronization
```

These may be implemented separately if real requirements emerge, and they would still not make this repo a Duende IdentityServer equivalent.

The project should resist becoming a miniature enterprise identity platform. OAuth here is a **token mint**. Authorization here is a **tenant framework**. Neither is an IdP.

The word `IdP` should be reserved for a component genuinely behaving as an identity provider. This repository is not that component. Do not treat `Novolis.Security.OAuth` as IdentityServer.

---

# 58. Extension philosophy

New capabilities should attach to explicit abstraction boundaries.

Examples:

```text
OIDC
    sits above OAuth

WebAuthn
    adds an Authentication credential mechanism

External identity provider federation
    adds an Authentication source

resource policies
    extend Authorization

persistent custom roles
    extend role providers

DPoP
    strengthens OAuth token binding
```

A new feature should not make unrelated core abstractions understand it.

---

# 59. Naming migration from Idp

Existing `Idp` naming should move toward the narrower responsibility.

Conceptually:

```text
Novolis.Security.Idp.Abstractions
    → Novolis.Security.OAuth.Abstractions

Novolis.Security.Idp
    → Novolis.Security.OAuth

Novolis.Security.Idp.AspNetCore
    → Novolis.Security.OAuth.AspNetCore

Novolis.Security.Idp.Storage
    → Novolis.Security.OAuth.Storage
```

Higher-level user-facing composition becomes:

```text
Novolis.Security.Authentication.*
```

Examples:

```text
IdpTokenService
    → OAuthTokenService / TokenIssuer

IdpOptions
    → OAuthOptions

IdpClient
    → OAuthClient

IdpRefreshToken
    → RefreshTokenRecord

IdpSigningKey
    → SigningKeyRecord
```

The word `IdP` should be reserved for a component genuinely behaving as an identity provider. The OAuth family is a **token mint**, not an IdP and not Duende IdentityServer. See [docs/what-this-is.md](docs/what-this-is.md).

---

# 60. Target end-state

A user signs in once:

```text
accounts.example.com
```

and receives a global authenticated identity:

```text
IdentityId
```

Different applications then obtain independent OAuth credentials:

```text
Space Game
    audience: space-game-api

Farming Simulator
    audience: farming-api
```

Each application performs authorization using:

```text
IdentityId
+
TenantId
+
Permission
```

Authorization relationships are composed from:

```text
Groups
    contain identities

Roles
    contain permissions

Composite roles
    contain roles

Assignments
    connect identities/groups to roles
    within a tenant
```

Application code generally protects capabilities using strongly typed declarations:

```csharp
[RequirePermission<Permissions.Moderator.Player.Kick>]
```

while structural checks remain possible:

```csharp
[RequireRole<Roles.Moderator>]
```

Built-in roles may live entirely in code.

Tenant administrators may define custom roles from the same permission catalog.

Composite roles provide explicit role composition without role inheritance.

The authentication system remains ignorant of all of this authorization structure.

The authorization system sees only the stable authenticated identity.

---

# 61. Core invariants

The architecture is considered correct only while these remain true:

1. **Identity is global.**
2. **Authorization is tenant-scoped.**
3. **Credential storage cannot identify the user by itself.**
4. **Credential references never become public identity identifiers.**
5. **Authentication does not own roles or permissions.**
6. **Authorization does not own credentials or authentication sessions.**
7. **OAuth scopes are not application permissions.**
8. **Groups contain identities.**
9. **Roles contain permissions.**
10. **Composite roles contain roles and form an acyclic graph.**
11. **Role assignment is tenant-scoped.**
12. **Permissions are the preferred application authorization primitive.**
13. **Built-in and store-backed roles resolve through the same authorization engine.**
14. **Custom roles cannot invent capabilities the application does not understand.**
15. **OAuth wire behavior remains standards-oriented.**
16. **Refresh-token rotation is atomic.**
17. **Authorization-code redemption is atomic and one-time.**
18. **Signing-key rollover does not invalidate otherwise valid access tokens.**
19. **Every resource server validates issuer and audience.**
20. **Default authorization is deny.**

---

# 62. One-sentence model

The complete system can be explained as:

> **Authentication establishes a global identity using a standards-based OAuth authority; Authorization decides what that identity may do inside a tenant, where groups contain identities, roles contain permissions, and composite roles contain roles.**

That sentence should remain true even as the implementation grows.