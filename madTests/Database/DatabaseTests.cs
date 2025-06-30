using System.Threading;

using FluentAssertions;

using microauthd.Data;
using microauthd.Services;

using madTypes.Common;
using madTypes.Api;
using madTypes.Api.Requests;

using madTests.Common;
using microauthd.Config;
using Microsoft.Data.Sqlite;

namespace madTests.Database
{
    public static class TestDb
    {
        public static void SetupDb(AppConfig config)
        {
            string randomDbFile = "test_" + System.Random.Shared.Next(1000, 99999).ToString() + ".db3";
            config.DbFile = randomDbFile;
            config.DbPass = "123456";

            DbInitializer.CreateDbTables(config);
            DbMigrations.ApplyMigrations();
        }

        public static void CleanupDb(AppConfig config)
        {
            Db.FlushWal();
            Db.Close();
            SqliteConnection.ClearAllPools();
            GC.Collect();
            GC.WaitForPendingFinalizers();
            
            Thread.Sleep(1000); // Give time for the database to close properly

            if (File.Exists(config.DbFile))
                File.Delete(config.DbFile);
        }
    }

    public class DatabaseTests
    {
        [Fact]
        public void CanCreateDatabase()
        {
            var config = TestHelpers.GetTestConfig();

            TestDb.SetupDb(config);

            File.Exists(config.DbFile).Should().BeTrue("Database file should be created when it does not exist.");

            TestDb.CleanupDb(config);
        }

        [Fact]
        public void CanCreateAndReadUser()
        {
            var config = TestHelpers.GetTestConfig();

            TestDb.SetupDb(config);

            var user = UserService.CreateUser("testuser", "test@example.com", "password123", config).Value;

            user.Should().NotBeNull("A created user should not be null.");

            var retrievedUser = UserService.GetUserById(user.Id).Value;

            retrievedUser.Should().NotBeNull("A retrieved user should not be null.");
            
            user.Id.Should().BeEquivalentTo(retrievedUser.Id);
            user.Username.Should().BeEquivalentTo(retrievedUser.Username);
            user.Email.Should().BeEquivalentTo(retrievedUser.Email);

            TestDb.CleanupDb(config);
        }

        [Fact]
        public void CanCreateAndReadClient()
        {
            var config = TestHelpers.GetTestConfig();
            
            TestDb.SetupDb(config);

            var client = ClientService.CreateClient(
                new CreateClientRequest { 
                    ClientId = "testclient", 
                    ClientSecret = "testsecret", 
                    DisplayName = "test client", 
                    Audience = "testaud" }, 
                config).Value;

            client.Should().NotBeNull("A created client should not be null.");
            
            var retrievedClient = ClientService.GetClientById(client.Id).Value;
            
            retrievedClient.Should().NotBeNull("A retrieved client should not be null.");
            
            client.Id.Should().BeEquivalentTo(retrievedClient.Id);
            client.ClientId.Should().BeEquivalentTo(retrievedClient.ClientId);
            client.Audience.Should().BeEquivalentTo(retrievedClient.Audience);
            client.DisplayName.Should().BeEquivalentTo(retrievedClient.DisplayName);

            TestDb.CleanupDb(config);
        }
    }
}
