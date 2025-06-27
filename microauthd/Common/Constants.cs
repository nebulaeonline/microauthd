namespace microauthd.Common;

public static class Constants
{
    // Role IDs
    public const string MadAdmin = "3855db1d-465e-412b-b1f4-b5cd78b4ae9f";

    public static readonly HashSet<string> ProtectedRoles = new()
    {
        MadAdmin
    };

    // Scope IDs
    public const string Scope_ProvisionUsers = "d0955db1-67f7-4a7b-a9bb-ffbef4f0d2bd";    // admin::provision_users
    public const string Scope_ResetPasswords = "2192998b-c3d3-4274-9a25-4a4195ba2ec7";   // admin::reset_passwords
    public const string Scope_DeactivateUsers = "31c00aae-4136-4a8c-92a6-d2bbf4be2d35";   // admin::deactivate_users
    public const string Scope_ReadUser = "1f4610fe-0cb2-4119-bd69-9b6033326998";          // admin::read_user
    public const string Scope_ListUsers = "b6348575-83ec-4288-801b-e0d2da20569c";         // admin::list_users
    
    public static readonly HashSet<string> ProtectedScopes = new()
    {
        Scope_ProvisionUsers,
        Scope_ResetPasswords,
        Scope_DeactivateUsers,
        Scope_ReadUser,
        Scope_ListUsers
    };
}
