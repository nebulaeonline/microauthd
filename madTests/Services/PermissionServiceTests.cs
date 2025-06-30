using FluentAssertions;

using madTypes.Api.Common;
using madTypes.Api.Requests;
using madTests.Common;
using madTests.Database;
using microauthd.Services;
using microauthd.Data;

namespace madTests.Services;

public class PermissionServiceTests
{
    [Fact]
    public void CanCreateUpdateAndDeletePermission()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        var newPerm = PermissionService.CreatePermission("NewPermission", config);

        newPerm.Should().NotBeNull("Creating a new permission should return a PermissionObject.");

        var allPerms = PermissionService.ListAllPermissions();

        allPerms.Should().NotBeNull("Listing all permissions should return a list of PermissionObjects.");
        allPerms.Value.Count().Should().Be(1, "There should be one permission after creation.");

        newPerm.Value.Name = "UpdatedPermission";
        PermissionService.UpdatePermission(newPerm.Value.Id, newPerm.Value, config);

        var updatedPerm = PermissionService.GetPermissionById(newPerm.Value.Id);

        updatedPerm.Should().NotBeNull("Retrieving the updated permission should return a PermissionObject.");

        updatedPerm.Value.Name.Should().Be("UpdatedPermission", "The permission name should be updated correctly.");

        PermissionService.DeletePermission(newPerm.Value.Id, config);

        var allPerms2 = PermissionService.ListAllPermissions();

        allPerms2.Should().NotBeNull("Listing all permissions after deletion should return a list of PermissionObjects.");

        allPerms2.Value.Count().Should().Be(0, "There should be no permissions after deletion.");
    }

    [Fact]
    public void CanAssignAndRemovePermissionsFromRole()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        var newPerm = PermissionService.CreatePermission("NewPermission", config);

        newPerm.Should().NotBeNull("Creating a new permission should return a PermissionObject.");

        var newRole = RoleService.CreateRole("NewRole", "This is a new role", config);

        newRole.Should().NotBeNull("Creating a new role should return a RoleObject.");

        var assignResult = PermissionService.AssignPermissionsToRole(newRole.Value.Id, newPerm.Value.Id, config);

        var rolePermissions = PermissionService.GetPermissionsForRole(newRole.Value.Id);

        rolePermissions.Should().NotBeNull("Retrieving permissions for a role should return a list of PermissionObjects.");

        rolePermissions.Value.Should().ContainSingle("There should be one permission assigned to the role after assignment.");

        PermissionService.RemovePermissionFromRole(newRole.Value.Id, newPerm.Value.Id, config);

        var newRolePermissions = PermissionService.GetPermissionsForRole(newRole.Value.Id);

        newRolePermissions.Should().NotBeNull("Retrieving permissions for a role after removal should return a list of PermissionObjects.");

        newRolePermissions.Value.Should().BeEmpty("There should be no permissions assigned to the role after removal.");
    }
}
