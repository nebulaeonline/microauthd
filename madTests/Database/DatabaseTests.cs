using FluentAssertions;

using microauthd.Data;
using microauthd.Services;

using madTypes.Common;
using madTypes.Api;

using madTests.Common;

namespace madTests.Database
{
    public class DatabaseTests
    {
        [Fact]
        public void CanCreateDatabase()
        {
            var config = TestHelpers.GetTestConfig();

            if (File.Exists(config.DbFile))
                File.Delete(config.DbFile);

            DbInitializer.CreateDbTables(config);

            File.Exists(config.DbFile).Should().BeTrue("Database file should be created when it does not exist.");
        }

        [Fact]
        public void CanCreateAndReadUser()
        {
            var config = TestHelpers.GetTestConfig();
            DbInitializer.CreateDbTables(config);

            var user = UserService.CreateUser("testuser", "test@example.com", "password123", config).Value;

            user.Should().NotBeNull("A created user should not be null.");

            var retrievedUser = UserService.GetUserById(user.Id).Value;

            retrievedUser.Should().NotBeNull("A retrieved user should not be null.");
            
            user.Id.Should().BeEquivalentTo(retrievedUser.Id);
            user.Username.Should().BeEquivalentTo(retrievedUser.Username);
            user.Email.Should().BeEquivalentTo(retrievedUser.Email);
        }
    }
}
