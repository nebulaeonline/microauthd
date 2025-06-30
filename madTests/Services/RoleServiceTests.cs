using FluentAssertions;

using madTypes.Api.Common;
using madTypes.Api.Requests;
using madTests.Common;
using madTests.Database;
using microauthd.Services;
using microauthd.Data;

namespace madTests.Services;

public class RoleServiceTests
{
    [Fact]
    public void CanUpdateRole()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        // Create a new role
        var createdRole = RoleService.CreateRole("NewRole", "This is a new role", config);
        createdRole.Should().NotBeNull("Role should be created successfully.");

        // Update the role
        createdRole.Value.Name = "UpdatedRole";
        createdRole.Value.Description = "This is  an updated role description.";

        RoleService.UpdateRole(createdRole.Value.Id, createdRole.Value, config);

        var updatedRole = RoleService.GetRoleById(createdRole.Value.Id);
        updatedRole.Should().NotBeNull("Updated role should be retrievable.");

        updatedRole.Value.Name.Should().Contain("Updated", "Role name should be updated.");
        updatedRole.Value.Description.Should().Contain("updated", "Role description should be updated.");

        TestDb.CleanupDb(config);
    }

    [Fact]
    public void CanListAllRoles()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        // Create 2 new roles
        var createdRole = RoleService.CreateRole("NewRole", "This is a new role", config);
        createdRole.Should().NotBeNull("Role should be created successfully.");

        var createdRole2 = RoleService.CreateRole("NewRole2", "This is a new role two", config);
        createdRole2.Should().NotBeNull("Role should be created successfully.");

        // List all roles
        var roleList = RoleService.ListAllRoles();
        roleList.Should().NotBeNull("Role list should not be null.");
        roleList.Value.Count().Should().Be(3, "There should be three roles in the list (MadAdmin is hard coded).");

        TestDb.CleanupDb(config);
    }

    [Fact]
    public void GetRoleIdByName_WorksAsIntended()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        // Create a new role
        var createdRole = RoleService.CreateRole("NewRole", "This is a new role", config);
        createdRole.Should().NotBeNull("Role should be created successfully.");

        // Get the role ID by name
        var roleId = RoleService.GetRoleIdByName("NewRole");
        roleId.Should().NotBeNull("Role ID should not be null.");

        roleId.Value.Should().Be(createdRole.Value.Id, "The retrieved role ID should match the created role ID.");
        TestDb.CleanupDb(config);
    }

    [Fact]
    public void CanListRolesForUser()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        // Create a new user
        var user = UserService.CreateUser("testuser", "test@example.com", "Password123", config);
        user.Should().NotBeNull("User should be created successfully.");

        // Create two new roles
        var role1 = RoleService.CreateRole("Role1", "This is role 1", config);
        role1.Should().NotBeNull("Role 1 should be created successfully.");

        var role2 = RoleService.CreateRole("Role2", "This is role 2", config);
        role2.Should().NotBeNull("Role 2 should be created successfully.");

        // Assign roles to the user
        RoleService.AddRoleToUser(user.Value.Id, role1.Value.Id, config);
        RoleService.AddRoleToUser(user.Value.Id, role2.Value.Id, config);

        // List roles for the user
        var userRoles = RoleService.ListRolesForUser(user.Value.Id);
        userRoles.Should().NotBeNull("User roles should not be null.");
        userRoles.Value.Count().Should().Be(2, "User should have two roles assigned.");

        TestDb.CleanupDb(config);
    }

    [Fact]
    public void CanDeleteRole()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        // Create a new role
        var createdRole = RoleService.CreateRole("NewRole", "This is a new role", config);
        createdRole.Should().NotBeNull("Role should be created successfully.");

        // List all roles
        var rolesBeforeDeletion = RoleService.ListAllRoles();
        rolesBeforeDeletion.Should().NotBeNull("Role list should not be null.");
        rolesBeforeDeletion.Value.Count().Should().Be(2, "There should be two roles in the list (MadAdmin is hard coded).");

        // Delete the role
        RoleService.DeleteRole(createdRole.Value.Id, config);

        // List all roles after deletion
        var rolesAfterDeletion = RoleService.ListAllRoles();
        rolesAfterDeletion.Should().NotBeNull("Role list should not be null after deletion.");
        rolesAfterDeletion.Value.Count().Should().Be(1, "There should be one role left in the list after deletion (MadAdmin is hard coded).");

        TestDb.CleanupDb(config);
    }

    [Fact]
    public void CanRemoveRoleFromUser()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        // Create a new user
        var user = UserService.CreateUser("testuser", "test@example.com", "Password123", config);
        user.Should().NotBeNull("User should be created successfully.");

        // Create a new role
        var role = RoleService.CreateRole("TestRole", "This is a test role", config);
        role.Should().NotBeNull("Role should be created successfully.");

        // Add the role to the user
        RoleService.AddRoleToUser(user.Value.Id, role.Value.Id, config);

        // List roles for the user before removal
        var userRolesBefore = RoleService.ListRolesForUser(user.Value.Id);
        userRolesBefore.Should().NotBeNull("User roles should not be null before removal.");
        userRolesBefore.Value.Count().Should().Be(1, "User should have one role assigned before removal.");

        // Remove the role from the user
        RoleService.RemoveRoleFromUser(user.Value.Id, role.Value.Id, config);

        // List roles for the user after removal
        var userRolesAfter = RoleService.ListRolesForUser(user.Value.Id);
        userRolesAfter.Should().NotBeNull("User roles should not be null after removal.");
        userRolesAfter.Value.Count().Should().Be(0, "User should have no roles assigned after removal.");

        TestDb.CleanupDb(config);
    }

    [Fact]
    public void CanAddAndRemoveRoleDTOsFromUserAndGetAllRoleDtosAndAllAssignedDtos()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        // Create a new user
        var user = UserService.CreateUser("testuser", "test@example.com", "Password123", config);
        user.Should().NotBeNull("User should be created successfully.");

        var role1 = RoleService.CreateRole("Role1", "This is role 1", config);
        role1.Should().NotBeNull("Role 1 should be created successfully.");
        var role2 = RoleService.CreateRole("Role2", "This is role 2", config);
        role2.Should().NotBeNull("Role 2 should be created successfully.");
        var role3 = RoleService.CreateRole("Role3", "This is role 3", config);
        role3.Should().NotBeNull("Role 3 should be created successfully.");
        var role4 = RoleService.CreateRole("Role4", "This is role 4", config);
        role4.Should().NotBeNull("Role 4 should be created successfully.");

        // Add two roles to the user
        RoleService.AddRoleToUser(user.Value.Id, role1.Value.Id, config);
        RoleService.AddRoleToUser(user.Value.Id, role2.Value.Id, config);

        // List roles for the user
        var rolesBefore = RoleService.ListRolesForUser(user.Value.Id);
        rolesBefore.Should().NotBeNull("User roles should not be null before adding DTOs.");
        rolesBefore.Value.Count().Should().Be(2, "User should have two roles assigned before adding DTOs.");

        // Create DTOs for the roles to add and remove
        var rolesToAdd = new List<RoleDto>
        {
            new RoleDto { Id = role1.Value.Id, Name = role1.Value.Name },
            new RoleDto { Id = role3.Value.Id, Name = role3.Value.Name },
            new RoleDto { Id = role4.Value.Id, Name = role4.Value.Name }
        };

        RoleAssignmentDto roleAssignment = new RoleAssignmentDto
        {
            UserId = user.Value.Id,
            Roles = rolesToAdd
        };

        // Add and remove roles using DTOs
        RoleService.ReplaceUserRoles(roleAssignment, config);

        // List roles for the user after adding DTOs
        var rolesAfterAdd = RoleService.ListRolesForUser(user.Value.Id);
        rolesAfterAdd.Should().NotBeNull("User roles should not be null after adding DTOs.");
        rolesAfterAdd.Value.Count().Should().Be(3, "User should have three roles assigned after adding DTOs.");

        // Getting Role DTOs should return the four roles created + MadAdmin
        var userRoleDtos = RoleService.GetAllRoleDtos();
        userRoleDtos.Should().NotBeNull("User role DTOs should not be null.");
        userRoleDtos.Value.Count().Should().Be(5, "There should be five role DTOs in the list (MadAdmin is hard coded).");

        // User Role DTOs should include the 3 roles assigned
        var userRoleDtosAssigned = RoleService.GetAssignedRoleDtos(user.Value.Id);
        userRoleDtosAssigned.Should().NotBeNull("User assigned role DTOs should not be null.");
        userRoleDtosAssigned.Value.Count().Should().Be(3, "User should have three assigned role DTOs.");

        var roleCount = RoleService.GetRoleCount();
        roleCount.Should().Be(5, "There should be five roles in total (MadAdmin + 4 created roles).");

        TestDb.CleanupDb(config);
    }
}
