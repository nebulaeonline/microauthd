using madTypes.Api.Common;
using FluentAssertions;
using madTests.Common;
using microauthd.Services;
using microauthd.Common;
using nebulae.dotArgon2;
using System.Text;
using microauthd.Data;
using madTests.Database;
using madTypes.Api.Requests;

namespace madTests.Services
{
    public class AuthServiceTests
    {
        [Fact]
        public void HashPassword_Produces_A_NonEmpty_String()
        {
            var config = TestHelpers.GetTestConfig();
            var hash = AuthService.HashPassword("correct horse battery staple", config);

            hash.Should().NotBeNullOrWhiteSpace();
            hash.Should().Contain("$argon2id");
        }

        [Fact]
        public void HashPassword_And_VerifyPassword_ShouldSucceed()
        {
            var config = TestHelpers.GetTestConfig();
            var password = "hunter2";

            var hash = AuthService.HashPassword(password, config);

            var isValid = Argon2.VerifyEncoded(Argon2.Argon2Algorithm.Argon2id, hash, System.Text.Encoding.UTF8.GetBytes(password));

            isValid.Should().BeTrue();
        }

        [Fact]
        public void VerifyPassword_ShouldFail_For_WrongPassword()
        {
            var config = TestHelpers.GetTestConfig();
            var password = "hunter2";
            var wrong = "hunter3";

            var hash = AuthService.HashPassword(password, config);
            var isValid = Argon2.VerifyEncoded(Argon2.Argon2Algorithm.Argon2id, hash, System.Text.Encoding.UTF8.GetBytes(wrong));

            isValid.Should().BeFalse();
        }

        [Theory]
        [InlineData(8)]
        [InlineData(16)]
        [InlineData(32)]
        public void GeneratePassword_ShouldReturn_CorrectLength(int length)
        {
            var result = AuthService.GeneratePassword(length);
            result.Should().HaveLength(length);
        }

        [Fact]
        public void GeneratePassword_ShouldThrow_IfTooShort()
        {
            var act = () => AuthService.GeneratePassword(4);
            act.Should().Throw<ArgumentOutOfRangeException>();
        }

        [Fact]
        public void AuthenticateUser_ShouldReturn_Success_ForValidCredentials()
        {
            var config = TestHelpers.GetTestConfig();

            TestDb.SetupDb(config);

            UserService.CreateUser(
                "testuser",
                "test@example.com",
                "password123",
                config);

            var userInfo = AuthService.AuthenticateUser("testuser", "password123", config);

            userInfo.Should().NotBeNull("User info should not be null for valid credentials.");
            userInfo.Value.Success.Should().BeTrue("Authentication should succeed for valid credentials.");
            userInfo.Value.Email.Should().Be("test@example.com");

            TestDb.CleanupDb(config);
        }

        [Fact]
        public void AuthenticateUser_ShouldReturn_Null_ForInvalidCredentials()
        {
            var config = TestHelpers.GetTestConfig();

            TestDb.SetupDb(config);

            UserService.CreateUser(
                "testuser",
                "test@example.com",
                "password123",                
                config);

            var userInfo = AuthService.AuthenticateUser("testuser", "wrongpassword", config);

            userInfo.Should().BeNull("User info should be null for invalid credentials.");

            TestDb.CleanupDb(config);
        }

        [Fact]
        public void AuthenticateClient_ShouldReturn_Success_ForValidCredentials()
        {
            var config = TestHelpers.GetTestConfig();
            
            TestDb.SetupDb(config);

            ClientService.CreateClient(new madTypes.Api.Requests.CreateClientRequest
            {
                ClientId = "testclient",
                ClientSecret = "testsecret",
                DisplayName = "Test Client",
                Audience = "testaud"
            }, config);

            var client = AuthService.AuthenticateClient("testclient", "testsecret", config);
            client.Should().NotBeNull("Client info should not be null for valid credentials.");

            TestDb.CleanupDb(config);
        }

        [Fact]
        public void AuthenticateClient_ShouldReturn_Null_ForInvalidCredentials()
        {
            var config = TestHelpers.GetTestConfig();

            TestDb.SetupDb(config);

            ClientService.CreateClient(new madTypes.Api.Requests.CreateClientRequest
            {
                ClientId = "testclient",
                ClientSecret = "testsecret",
                DisplayName = "Test Client",
                Audience = "testaud"
            }, config);

            var client = AuthService.AuthenticateClient("testclient", "wrongsecret", config);
            client.Should().BeNull("Client info should be null for invalid credentials.");

            TestDb.CleanupDb(config);
        }

        [Fact]
        public void ValidateOidcClient_ShouldReturn_True_ForValidClient()
        {
            var config = TestHelpers.GetTestConfig();
            TestDb.SetupDb(config);

            ClientService.CreateClient(new madTypes.Api.Requests.CreateClientRequest
            {
                ClientId = "validclient",
                ClientSecret = "validsecret",
                DisplayName = "Valid Client",
                Audience = "validaud"
            }, config);

            var isValid = AuthService.ValidateOidcClient("validclient", "validsecret", config);
            isValid.Should().BeTrue("Validation should succeed for valid client credentials.");
            
            TestDb.CleanupDb(config);
        }

        [Fact]
        public void ValidateOidcClient_ShouldReturn_False_ForInvalidClient()
        {
            var config = TestHelpers.GetTestConfig();
            TestDb.SetupDb(config);

            ClientService.CreateClient(new madTypes.Api.Requests.CreateClientRequest
            {
                ClientId = "validclient",
                ClientSecret = "validsecret",
                DisplayName = "Valid Client",
                Audience = "validaud"
            }, config);

            var isValid = AuthService.ValidateOidcClient("validclient", "wrongsecret", config);
            isValid.Should().BeFalse("Validation should fail for invalid client credentials.");

            TestDb.CleanupDb(config);
        }

        [Fact]
        public void GetExpectedAudience_ShouldReturn_Audience_ForValidClient()
        {
            var config = TestHelpers.GetTestConfig();
            TestDb.SetupDb(config);

            ClientService.CreateClient(new madTypes.Api.Requests.CreateClientRequest
            {
                ClientId = "validclient",
                ClientSecret = "validsecret",
                DisplayName = "Valid Client",
                Audience = "validaud1234"
            }, config);

            var audience = AuthService.GetExpectedAudienceForClient("validclient");
            audience.Should().Be("validaud1234");

            TestDb.CleanupDb(config);
        }

        [Fact]
        public void RecordFailedLogin_ShouldReturn_NumberOfFailedLogins()
        {
            var config = TestHelpers.GetTestConfig();

            TestDb.SetupDb(config);

            var user = UserService.CreateUser(
                "testuser",
                "test@example.com",
                "password123",
                config).Value;

            AuthService.RecordFailedLogin(user.Id, config);
            AuthService.RecordFailedLogin(user.Id, config);

            var failedLogins = AuthService.GetFailedLoginAttempts(user.Id);

            failedLogins.Should().Be(2);

            TestDb.CleanupDb(config);
        }
    }
}
