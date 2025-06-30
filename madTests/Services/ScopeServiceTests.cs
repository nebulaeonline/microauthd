using FluentAssertions;

using madTypes.Api.Common;
using madTypes.Api.Requests;
using madTests.Common;
using madTests.Database;
using microauthd.Services;
using microauthd.Data;

namespace madTests.Services;

public class ScopeServiceTests
{
    [Fact]
    public void CanCreateUpdateAndDeleteScope()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        // Create two new scopes
        ScopeObject scope1 = new ScopeObject
        {
            Name = "test_scope1",
            Description = "Test Scope1 Description"
        };

        ScopeObject scope2 = new ScopeObject
        {
            Name = "test_scope2",
            Description = "Test Scope2 Description"
        };

        var createdScope1 = ScopeService.CreateScope(scope1, config);
        createdScope1.Success.Should().BeTrue("Scope creation should succeed.");
        createdScope1.Value.Should().NotBeNull("Created scope should not be null.");
        var createdScope2 = ScopeService.CreateScope(scope2, config);
        createdScope2.Success.Should().BeTrue("Scope creation should succeed.");
        createdScope2.Value.Should().NotBeNull("Created scope should not be null.");

        // Verify the scopes were created
        var scopeList = ScopeService.ListAllScopes();
        scopeList.Success.Should().BeTrue("Scope listing should succeed.");
        scopeList.Value.Count().Should().Be(7, "There should be 7 scopes- 2 added and 5 default scopes.");

        // Update the first scope
        ScopeObject editScope1 = new ScopeObject
        {
            Id = createdScope1.Value.Id,
            Name = "updated_test_scope1",
            Description = "Updated Test Scope1 Description",
        };

        ScopeService.UpdateScope(editScope1.Id, editScope1, config);

        // Verify the scope was updated
        var updatedScope1 = ScopeService.GetScopeById(editScope1.Id);
        updatedScope1.Success.Should().BeTrue("Scope retrieval should succeed after update.");
        updatedScope1.Value.Should().NotBeNull("Updated scope should not be null.");
        updatedScope1.Value.Name.Should().Be(editScope1.Name, "Updated scope name should match.");
        updatedScope1.Value.Description.Should().Be(editScope1.Description, "Updated scope description should match.");

        // Try to get the scope id by name
        var scopeByName = ScopeService.GetScopeIdByName(editScope1.Name);
        scopeByName.Success.Should().BeTrue("Scope retrieval by name should succeed.");
        scopeByName.Value.Should().Be(editScope1.Id, "Scope ID by name should match the updated scope ID.");

        // Delete the second scope
        ScopeService.DeleteScope(createdScope2.Value.Id, config);

        // Get the scope count after deletion - should be 6 (1 updated + 5 default scopes)
        var scopeCountAfterDeletion = ScopeService.GetScopeCount();
        scopeCountAfterDeletion.Should().Be(6, "Scope count should be 6 after deleting one scope.");

        // Create a new user and a new client
        var user = UserService.CreateUser("testuser", "test@example.com", "Password123", config);
        user.Success.Should().BeTrue("User creation should succeed.");
        var client = ClientService.CreateClient(new CreateClientRequest
        {
            ClientId = "testclient",
            DisplayName = "Test Client",
            ClientSecret = "topsecret",
            Audience = "testaud"
        }, config);
        client.Success.Should().BeTrue("Client creation should succeed.");
        client.Value.Should().NotBeNull("Created client should not be null.");

        // Assign the updated scope to the user
        var assignScopeResult = ScopeService.AddScopesToUser(user.Value.Id, new AssignScopesRequest
        {
            ScopeIds = new List<string> { updatedScope1.Value.Id }
        }, config);
        assignScopeResult.Success.Should().BeTrue("Assigning scope to user should succeed.");

        // Verify the user has the updated scope
        var userScopes = ScopeService.ListScopesForUser(user.Value.Id);
        userScopes.Success.Should().BeTrue("Listing scopes for user should succeed.");
        userScopes.Value.Should().NotBeNull("User scopes should not be null.");
        userScopes.Value.First().Name.Contains("updated_test_scope1").Should().BeTrue("User should have the updated scope.");

        // remove the updated scope from the user
        ScopeService.RemoveScopeFromUser(user.Value.Id, updatedScope1.Value.Id, config);

        // Verify the user no longer has the updated scope
        var userScopesAfterRemoval = ScopeService.ListScopesForUser(user.Value.Id);
        userScopesAfterRemoval.Success.Should().BeTrue("Listing scopes for user after removal should succeed.");
        userScopesAfterRemoval.Value.Count().Should().Be(0, "User should have no scopes after removal.");

        // Assign the updated scope to the client
        ScopeService.AddScopesToClient(client.Value.Id, new AssignScopesRequest
        {
            ScopeIds = new List<string> { updatedScope1.Value.Id }
        }, config);

        // Verify the client has the updated scope
        var clientScopes = ScopeService.GetScopesForClient(client.Value.Id);
        clientScopes.Success.Should().BeTrue("Listing scopes for client should succeed.");
        clientScopes.Value.Should().NotBeNull("Client scopes should not be null.");
        clientScopes.Value.First().Name.Contains("updated_test_scope1").Should().BeTrue("Client should have the updated scope.");

        // Remove the updated scope from the client
        ScopeService.RemoveScopeFromClient(client.Value.Id, updatedScope1.Value.Id, config);

        // Verify the client no longer has the updated scope
        var clientScopesAfterRemoval = ScopeService.GetScopesForClient(client.Value.Id);
        clientScopesAfterRemoval.Success.Should().BeTrue("Listing scopes for client after removal should succeed.");
        clientScopesAfterRemoval.Value.Count().Should().Be(0, "Client should have no scopes after removal.");

        TestDb.CleanupDb(config);
    }
}
