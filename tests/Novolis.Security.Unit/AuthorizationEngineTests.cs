using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Novolis.Security.Authentication;
using Novolis.Security.Authorization;
using TUnit.Core;

namespace Novolis.Security.Tests;

public class AuthorizationEngineTests
{
    [Test]
    public async Task DefaultDeny_AndDirectPermissionGrantViaRole()
    {
        await using var provider = CreateProvider();
        var tenant = TenantId.New();
        var identity = IdentityId.New();
        var authz = provider.GetRequiredService<IAuthorizationService>();
        var denied = await authz.AuthorizeAsync(identity, tenant, AuthorizationIds.Permission<Kick>());
        await Assert.That(denied.Succeeded).IsFalse();

        await provider.GetRequiredService<IRoleAssignmentStore>()
            .AssignIdentityAsync(new IdentityRoleAssignment(tenant, identity, AuthorizationIds.Role<Moderator>()));
        var allowed = await authz.AuthorizeAsync(identity, tenant, AuthorizationIds.Permission<Kick>());
        await Assert.That(allowed.Succeeded).IsTrue();
    }

    [Test]
    public async Task GroupAssignment_GrantsPermissions_RoleCheckRemainsExact()
    {
        await using var provider = CreateProvider();
        var tenant = TenantId.New();
        var identity = IdentityId.New();
        var group = new Group(GroupId.New(), tenant, "Moderators");
        await provider.GetRequiredService<IGroupStore>().UpsertAsync(group);
        await provider.GetRequiredService<IGroupMembershipStore>()
            .AddAsync(new GroupMembership(tenant, group.Id, identity));
        await provider.GetRequiredService<IRoleAssignmentStore>()
            .AssignGroupAsync(new GroupRoleAssignment(tenant, group.Id, AuthorizationIds.Role<Moderator>()));

        var authz = provider.GetRequiredService<IAuthorizationService>();
        await Assert.That((await authz.AuthorizeAsync(identity, tenant, AuthorizationIds.Permission<Kick>())).Succeeded)
            .IsTrue();
        await Assert.That((await authz.AuthorizeRoleAsync(identity, tenant, AuthorizationIds.Role<Moderator>())).Succeeded)
            .IsTrue();
    }

    [Test]
    public async Task CompositeRole_ExpandsPermissions_ButIsNotTheContainedRole()
    {
        await using var provider = CreateProvider();
        var tenant = TenantId.New();
        var identity = IdentityId.New();
        await provider.GetRequiredService<IRoleStore>().UpsertAsync(new RoleDefinition(
            new RoleId("senior-moderator"),
            tenant,
            new HashSet<PermissionId>(),
            new HashSet<RoleId> { AuthorizationIds.Role<Moderator>() },
            IsBuiltIn: false));
        await provider.GetRequiredService<IRoleAssignmentStore>()
            .AssignIdentityAsync(new IdentityRoleAssignment(tenant, identity, new RoleId("senior-moderator")));

        var authz = provider.GetRequiredService<IAuthorizationService>();
        await Assert.That((await authz.AuthorizeAsync(identity, tenant, AuthorizationIds.Permission<Kick>())).Succeeded)
            .IsTrue();
        await Assert.That((await authz.AuthorizeRoleAsync(identity, tenant, AuthorizationIds.Role<Moderator>())).Succeeded)
            .IsFalse();
        await Assert.That((await authz.AuthorizeRoleAsync(identity, tenant, new RoleId("senior-moderator"))).Succeeded)
            .IsTrue();
    }

    [Test]
    public async Task CrossTenantAssignments_DoNotLeak()
    {
        await using var provider = CreateProvider();
        var space = TenantId.New();
        var farm = TenantId.New();
        var identity = IdentityId.New();
        await provider.GetRequiredService<IRoleAssignmentStore>()
            .AssignIdentityAsync(new IdentityRoleAssignment(space, identity, AuthorizationIds.Role<Moderator>()));

        var authz = provider.GetRequiredService<IAuthorizationService>();
        await Assert.That((await authz.AuthorizeAsync(identity, space, AuthorizationIds.Permission<Kick>())).Succeeded)
            .IsTrue();
        await Assert.That((await authz.AuthorizeAsync(identity, farm, AuthorizationIds.Permission<Kick>())).Succeeded)
            .IsFalse();
    }

    [Test]
    public async Task UnknownStoredPermission_AndCycles_AreRejected()
    {
        await using var provider = CreateProvider();
        var tenant = TenantId.New();
        var store = provider.GetRequiredService<IRoleStore>();
        await Assert.That(async () => await store.UpsertAsync(new RoleDefinition(
            new RoleId("invented"),
            tenant,
            new HashSet<PermissionId> { new("not.a.real.permission") },
            new HashSet<RoleId>(),
            IsBuiltIn: false))).Throws<InvalidOperationException>();

        await store.UpsertAsync(new RoleDefinition(
            new RoleId("a"),
            tenant,
            new HashSet<PermissionId>(),
            new HashSet<RoleId> { new("b") },
            IsBuiltIn: false));
        await Assert.That(async () => await store.UpsertAsync(new RoleDefinition(
            new RoleId("b"),
            tenant,
            new HashSet<PermissionId>(),
            new HashSet<RoleId> { new("a") },
            IsBuiltIn: false))).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task CacheInvalidates_WhenMembershipChanges()
    {
        await using var provider = CreateProvider();
        var tenant = TenantId.New();
        var identity = IdentityId.New();
        var group = new Group(GroupId.New(), tenant, "Moderators");
        var memberships = provider.GetRequiredService<IGroupMembershipStore>();
        var assignments = provider.GetRequiredService<IRoleAssignmentStore>();
        var authz = provider.GetRequiredService<IAuthorizationService>();
        await provider.GetRequiredService<IGroupStore>().UpsertAsync(group);
        await memberships.AddAsync(new GroupMembership(tenant, group.Id, identity));
        await assignments.AssignGroupAsync(new GroupRoleAssignment(tenant, group.Id, AuthorizationIds.Role<Moderator>()));
        await Assert.That((await authz.AuthorizeAsync(identity, tenant, AuthorizationIds.Permission<Kick>())).Succeeded)
            .IsTrue();

        await memberships.RemoveAsync(new GroupMembership(tenant, group.Id, identity));
        await Assert.That((await authz.AuthorizeAsync(identity, tenant, AuthorizationIds.Permission<Kick>())).Succeeded)
            .IsFalse();
    }

    [Test]
    public async Task Defaults_UseLoggerAuthorizationEventSink()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddNovolisAuthorization();
        await using var provider = services.BuildServiceProvider();
        await Assert.That(provider.GetRequiredService<IAuthorizationEventSink>().GetType())
            .IsEqualTo(typeof(LoggerAuthorizationEventSink));
    }

    [Test]
    public async Task DeniedAuthorization_IsRecordedWithoutSecrets()
    {
        var events = new RecordingAuthorizationEventSink();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddNovolisAuthorization();
        services.AddPermission<Kick>();
        services.Replace(ServiceDescriptor.Singleton<IAuthorizationEventSink>(events));
        await using var provider = services.BuildServiceProvider();
        var identity = IdentityId.New();
        var tenant = TenantId.New();
        var denied = await provider.GetRequiredService<IAuthorizationService>()
            .AuthorizeAsync(identity, tenant, AuthorizationIds.Permission<Kick>());
        await Assert.That(denied.Succeeded).IsFalse();
        await Assert.That(events.Last).IsNotNull();
        await Assert.That(events.Last!.Type).IsEqualTo(AuthorizationEventTypes.AuthorizationDenied);
        await Assert.That(events.Last.PermissionId).IsEqualTo(AuthorizationIds.Permission<Kick>().Value);
        await Assert.That(events.Last.IdentityId).IsEqualTo(identity);
    }

    static ServiceProvider CreateProvider()
    {
        var services = new ServiceCollection();
        services.AddNovolisAuthorization();
        services.AddPermission<Kick>();
        services.AddPermission<Ban>();
        services.AddBuiltInRole<Moderator>();
        return services.BuildServiceProvider();
    }

    public sealed class Kick : IPermission
    {
        public static string Value => "moderator.player.kick";
    }

    public sealed class Ban : IPermission
    {
        public static string Value => "moderator.player.ban";
    }

    public sealed class Moderator : IBuiltInRole
    {
        public static string Value => "moderator";

        public static IReadOnlySet<PermissionId> Permissions { get; } =
            new HashSet<PermissionId> { AuthorizationIds.Permission<Kick>(), AuthorizationIds.Permission<Ban>() };
    }

    sealed class RecordingAuthorizationEventSink : IAuthorizationEventSink
    {
        public AuthorizationSecurityEvent? Last { get; private set; }

        public ValueTask RecordAsync(
            AuthorizationSecurityEvent securityEvent,
            CancellationToken cancellationToken = default)
        {
            Last = securityEvent;
            return ValueTask.CompletedTask;
        }
    }
}
