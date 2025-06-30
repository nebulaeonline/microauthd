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
}
