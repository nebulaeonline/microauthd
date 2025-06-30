using FluentAssertions;

using madTypes.Api.Common;
using madTypes.Api.Requests;
using madTests.Common;
using madTests.Database;
using microauthd.Services;
using microauthd.Data;

namespace madTests.Services;

public class UserServiceTests
{
    [Fact]
    public void CanCreateAndUpdateUserAndMarkEmailAsVerifiedAndListUsers()
    {
        var config = TestHelpers.GetTestConfig();
        TestDb.SetupDb(config);

        // Create a new user
        var user = UserService.CreateUser("testuser", "test@example.com", "Password123", config);
        user.Success.Should().BeTrue("User creation should succeed.");
        user.Value.Should().NotBeNull("Created user should not be null.");

        user.Value.Username = "updatedtestuser";
        user.Value.Email = "updated@example.com";

        // Update the user
        var updated = UserService.UpdateUser(user.Value.Id, user.Value, config);
        updated.Success.Should().BeTrue("User update should succeed.");
        updated.Value.Should().NotBeNull("Updated user should not be null.");

        // Verify the user was updated
        updated.Value.Username.Should().Be("updatedtestuser", "Updated username should match.");
        updated.Value.Email.Should().Be("updated@example.com", "Updated email should match.");

        // Mark the email as verified
        UserService.MarkEmailVerified(updated.Value.Id);

        // Verify the email was marked as verified
        var verifiedUser = UserService.GetUserById(updated.Value.Id);
        verifiedUser.Success.Should().BeTrue("User retrieval should succeed after email verification.");
        verifiedUser.Value.Should().NotBeNull("Verified user should not be null.");
        verifiedUser.Value.EmailVerified.Should().BeTrue("Email should be marked as verified.");

        // List users and verify the created & updated user is present
        var userList = UserService.ListUsers();
        userList.Success.Should().BeTrue("User listing should succeed.");
        userList.Value.Should().NotBeNull("User list should not be null.");
        userList.Value.Count().Should().Be(1, "There should be one user in the list after creation and update.");

        // Try getting the user id by username
        var userIdByUsername = UserService.GetUserIdByUsername("updatedtestuser");
        userIdByUsername.Success.Should().BeTrue("User retrieval by username should succeed.");
        userIdByUsername.Value.Should().Be(updated.Value.Id, "User ID by username should match the updated user ID.");

        // Deactivate the user
        UserService.DeactivateUser(updated.Value.Id, config);

        // Get inactive user count after deactivation
        var inactiveUserCount = UserService.GetInactiveUserCount();
        inactiveUserCount.Should().Be(1, "Inactive user count should be 1 after deactivating the user.");

        // Re-Activate the user
        UserService.ReactivateUser(updated.Value.Id, config);
        var inactiveUserCountAfterReactivation = UserService.GetInactiveUserCount();
        inactiveUserCountAfterReactivation.Should().Be(0, "Inactive user count should be 0 after reactivating the user.");

        // Update the user's password
        var passwordUpdateResult = UserService.ResetUserPassword(updated.Value.Id, "NewPassword123", config);
        passwordUpdateResult.Success.Should().BeTrue("Password update should succeed.");
        var resetPass = AuthService.AuthenticateUser("updatedtestuser", "NewPassword123", config);
        resetPass.Should().NotBeNull("Authentication result should not be null after password reset.");
        resetPass.Value.Success.Should().BeTrue("User should be able to authenticate with new password");

        // Delete the user
        UserService.DeleteUser(updated.Value.Id, config);

        // Verify the user was deleted
        var userCountAfterDeletion = UserService.GetUserCount();
        userCountAfterDeletion.Should().Be(0, "User count should be 0 after deleting the user.");

        // Cleanup the test database
        TestDb.CleanupDb(config);
    }
}
