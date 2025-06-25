using FluentAssertions;
using madTests.Common;
using microauthd.Services;
using microauthd.Common;
using nebulae.dotArgon2;
using System.Text;

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
    }
}
