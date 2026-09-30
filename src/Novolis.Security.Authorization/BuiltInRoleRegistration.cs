namespace Novolis.Security.Authorization;

internal sealed class BuiltInRoleRegistration<TRole> : IBuiltInRoleRegistration
    where TRole : IBuiltInRole
{
    public void Apply(BuiltInRoleRegistry registry) => registry.Add<TRole>();
}
