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

    [Fact]
    public void CanGetPermissionIdByName()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        var newPerm = PermissionService.CreatePermission("TestPermission", config);
        newPerm.Should().NotBeNull("Creating a new permission should return a PermissionObject.");

        var permId = PermissionService.GetPermissionIdByName("TestPermission");
        permId.Should().NotBeNull("Retrieving permission ID by name should return a valid ID.");
        permId.Value.Should().Be(newPerm.Value.Id, "The retrieved permission ID should match the created permission ID.");

        TestDb.CleanupDb(config);
    }

    [Fact]
    public void CanGetEffectivePermissionsForUser()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        var user = UserService.CreateUser("testuser", "test@example.com", "Password123", config);
        user.Should().NotBeNull("Creating a new user should return a UserObject.");

        var role = RoleService.CreateRole("TestRole", "A test role", config);
        role.Should().NotBeNull("Creating a new role should return a RoleObject.");

        var perm1 = PermissionService.CreatePermission("TestPermission1", config);
        perm1.Should().NotBeNull("Creating a new permission should return a PermissionObject.");

        var perm2 = PermissionService.CreatePermission("TestPermission2", config);
        perm2.Should().NotBeNull("Creating a second permission should return a PermissionObject.");

        // Assign permissions to role
        PermissionService.AssignPermissionsToRole(role.Value.Id, perm1.Value.Id, config);
        PermissionService.AssignPermissionsToRole(role.Value.Id, perm2.Value.Id, config);

        // Assign role to user
        RoleService.AddRoleToUser(user.Value.Id, role.Value.Id, config);

        var effectivePermissions = PermissionService.GetEffectivePermissionsForUser(user.Value.Id);

        effectivePermissions.Should().NotBeNull("Retrieving effective permissions for a user should return a list of PermissionObjects.");
        effectivePermissions.Value.Count().Should().Be(2, "The user should have two effective permissions from the assigned role.");

        TestDb.CleanupDb(config);
    }

    [Fact]
    public void CanCheckIfUserHasPermission()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        var user = UserService.CreateUser("testuser", "test@example.com", "Password123", config);
        user.Should().NotBeNull("Creating a new user should return a UserObject.");

        var role = RoleService.CreateRole("TestRole", "A test role", config);
        role.Should().NotBeNull("Creating a new role should return a RoleObject.");

        var perm1 = PermissionService.CreatePermission("TestPermission1", config);
        perm1.Should().NotBeNull("Creating a new permission should return a PermissionObject.");

        // Assign permissions to role
        PermissionService.AssignPermissionsToRole(role.Value.Id, perm1.Value.Id, config);

        // Assign role to user
        RoleService.AddRoleToUser(user.Value.Id, role.Value.Id, config);

        var hasPermission = PermissionService.UserHasPermission(user.Value.Id, perm1.Value.Id);

        hasPermission.Should().NotBeNull("Checking if user has permission should return an ApiResult.");

        hasPermission.Value.Allowed.Should().BeTrue("The user should have the permission assigned through the role.");

        TestDb.CleanupDb(config);
    }

    [Fact]
    public void CanGetPermissionsForRole()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        var role = RoleService.CreateRole("TestRole", "A test role", config);
        role.Should().NotBeNull("Creating a new role should return a RoleObject.");

        var perm1 = PermissionService.CreatePermission("TestPermission1", config);
        perm1.Should().NotBeNull("Creating a new permission should return a PermissionObject.");

        var perm2 = PermissionService.CreatePermission("TestPermission2", config);
        perm2.Should().NotBeNull("Creating a second permission should return a PermissionObject.");

        // Assign permissions to role
        PermissionService.AssignPermissionsToRole(role.Value.Id, perm1.Value.Id, config);
        PermissionService.AssignPermissionsToRole(role.Value.Id, perm2.Value.Id, config);

        var permissionsForRole = PermissionService.GetPermissionsForRole(role.Value.Id);

        permissionsForRole.Should().NotBeNull("Retrieving permissions for a role should return a list of PermissionObjects.");
        permissionsForRole.Value.Count().Should().Be(2, "The role should have two permissions assigned.");

        TestDb.CleanupDb(config);
    }

    [Fact]
    public void CanGetAllPermissionDTOs()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        var role = RoleService.CreateRole("TestRole", "A test role", config);
        role.Should().NotBeNull("Creating a new role should return a RoleObject.");

        var perm1 = PermissionService.CreatePermission("TestPermission1", config);
        perm1.Should().NotBeNull("Creating a new permission should return a PermissionObject.");

        var perm2 = PermissionService.CreatePermission("TestPermission2", config);
        perm2.Should().NotBeNull("Creating a second permission should return a PermissionObject.");

        // Assign permissions to role
        PermissionService.AssignPermissionsToRole(role.Value.Id, perm1.Value.Id, config);
        PermissionService.AssignPermissionsToRole(role.Value.Id, perm2.Value.Id, config);

        var permissionDTOs = PermissionService.GetAllPermissionDtos();

        permissionDTOs.Should().NotBeNull("Retrieving all permission DTOs should return a list of PermissionDTOs.");
        permissionDTOs.Value.Count().Should().Be(2, "Permission DTOs should match the number of permissions created.");

        TestDb.CleanupDb(config);
    }

    [Fact]
    public void CanGetPermissionsDTOsForRole()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        var role = RoleService.CreateRole("TestRole", "A test role", config);
        role.Should().NotBeNull("Creating a new role should return a RoleObject.");

        var perm1 = PermissionService.CreatePermission("TestPermission1", config);
        perm1.Should().NotBeNull("Creating a new permission should return a PermissionObject.");

        var perm2 = PermissionService.CreatePermission("TestPermission2", config);
        perm2.Should().NotBeNull("Creating a second permission should return a PermissionObject.");

        // Assign permissions to role
        PermissionService.AssignPermissionsToRole(role.Value.Id, perm1.Value.Id, config);
        PermissionService.AssignPermissionsToRole(role.Value.Id, perm2.Value.Id, config);

        var permissionsDTOsForRole = PermissionService.GetAssignedPermissionDtos(role.Value.Id);

        permissionsDTOsForRole.Should().NotBeNull("Retrieving permissions for a role should return a list of PermissionObjects.");
        permissionsDTOsForRole.Value.Count().Should().Be(2, "The role should have two permissions assigned.");

        TestDb.CleanupDb(config);
    }

    [Fact]
    public void CanAddAndRemovePermissionDTOsFromRole()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        var role = RoleService.CreateRole("TestRole", "A test role", config);
        role.Should().NotBeNull("Creating a new role should return a RoleObject.");

        var perm1 = PermissionService.CreatePermission("TestPermission1", config);
        perm1.Should().NotBeNull("Creating a new permission should return a PermissionObject.");

        var perm2 = PermissionService.CreatePermission("TestPermission2", config);
        perm2.Should().NotBeNull("Creating a second permission should return a PermissionObject.");

        // Assign permissions to role
        PermissionService.AssignPermissionsToRole(role.Value.Id, perm1.Value.Id, config);
        PermissionService.AssignPermissionsToRole(role.Value.Id, perm2.Value.Id, config);

        var perm3 = PermissionService.CreatePermission("TestPermission3", config);
        perm3.Should().NotBeNull("Creating a third permission should return a PermissionObject.");

        var perm4 = PermissionService.CreatePermission("TestPermission4", config);
        perm4.Should().NotBeNull("Creating a fourth permission should return a PermissionObject.");

        // Set up permission DTOs to add/remove from the Role
        var permissionDTOsToAdd = new List<PermissionDto>
        {
            new PermissionDto { Id = perm1.Value.Id, Name = perm1.Value.Name },
            new PermissionDto { Id = perm3.Value.Id, Name = perm3.Value.Name },
            new PermissionDto { Id = perm4.Value.Id, Name = perm4.Value.Name }
        };

        PermissionAssignmentDto assignmentDto = new PermissionAssignmentDto
        {
            RoleId = role.Value.Id,
            Permissions = permissionDTOsToAdd
        };

        // Add/Remove permissions from the role
        var addResult = PermissionService.ReplaceRolePermissions(assignmentDto, config);

        var rolePermissions = PermissionService.GetPermissionsForRole(role.Value.Id);
        rolePermissions.Should().NotBeNull("Retrieving permissions for a role should return a list of PermissionObjects.");

        rolePermissions.Value.Count().Should().Be(3, "The role should have three permissions after adding 4 and deleting 1.");

        TestDb.CleanupDb(config);
    }

    [Fact]
    public void GetPermissionsCountWorks()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        var perm1 = PermissionService.CreatePermission("TestPermission1", config);
        perm1.Should().NotBeNull("Creating a new permission should return a PermissionObject.");

        var perm2 = PermissionService.CreatePermission("TestPermission2", config);
        perm2.Should().NotBeNull("Creating a second permission should return a PermissionObject.");

        PermissionService.GetPermissionCount().Should().Be(2, "The count function should return that two permissions exist in the system.");

        TestDb.CleanupDb(config);
    }
}
