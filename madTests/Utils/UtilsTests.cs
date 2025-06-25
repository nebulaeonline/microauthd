using microauthd.Common;
using microauthd.Services;
using System.Text;
using FluentAssertions;
namespace madTests.UtilsTests;

// Utility tests
public class UtilsTests
{
    [Fact]
    public void IsValidIp_ValidIp_ReturnsTrue()
    {
        var result = Utils.IsValidIpAddress("127.0.0.1");
        result.Should().BeTrue();
    }

    [Fact]
    public void IsValidIp_InvalidIp_ReturnsFalse()
    {
        var result = Utils.IsValidIpAddress("999.999.999.999");
        result.Should().BeFalse();
    }

    [Fact]
    public void IsValidEmail_ValidEmail_ReturnsTrue()
    {
        var result = Utils.IsValidEmail("r@example.com");
        result.Should().BeTrue();
    }

    [Fact]
    public void IsValidEmail_InvalidEmail_ReturnsFalse()
    {
        var result = Utils.IsValidEmail("invalid-email");
        result.Should().BeFalse();
    }

    [Fact]
    public void IsPowerOfTwo_ValidPowerOfTwo_ReturnsTrue()
    {
        var result = Utils.IsPowerOfTwo(8);
        result.Should().BeTrue();
    }

    [Fact]
    public void IsPowerOfTwo_InvalidPowerOfTwo_ReturnsFalse()
    {
        var result = Utils.IsPowerOfTwo(11);
        result.Should().BeFalse();
    }

    [Fact]
    public void GenerateBase64EncodedRandomBytes_Produces_CorrectLength()
    {
        var result = Utils.GenerateBase64EncodedRandomBytes(16);
        result.Should().NotBeNullOrEmpty();
        result.Length.Should().Be(22);
    }

    [Fact]
    public void GenerateBase64EncodedRandomBytes_ReturnsDifferentResults()
    {
        var a = Utils.GenerateBase64EncodedRandomBytes(16);
        var b = Utils.GenerateBase64EncodedRandomBytes(16);
        a.Should().NotBe(b);
    }

    [Fact]
    public void GenerateSalt_Generates_CorrectLengthSalt()
    {
        var salt = Utils.GenerateSalt(16);
        Assert.NotNull(salt);
        Assert.Equal(16, salt.Length);
    }

    [Fact]
    public void GenerateSalt_Returns_DifferentValues()
    {
        var salt1 = Utils.GenerateSalt(16);
        var salt2 = Utils.GenerateSalt(16);
        Assert.NotEqual(salt1, salt2);
    }

    [Fact]
    public void Base64UrlEncoding_KnownInput_ProducesExpectedResult()
    {
        // Raw input bytes (ASCII "foobar")
        var input = System.Text.Encoding.ASCII.GetBytes("foobar");

        // Raw Base64: Zm9vYmFy
        // Base64-URL: Zm9vYmFy (same, no + or /, and no padding)
        var result = Utils.Base64Url(input);

        result.Should().Be("Zm9vYmFy");
    }

    [Fact]
    public void Base64UrlEncoding_ProducesUrlSafeOutput()
    {
        byte[] input = new byte[] { 0xfb, 0xff, 0xef };

        // Regular Base64: +//v
        // Base64 URL-safe: -__v
        var result = Utils.Base64Url(input);

        result.Should().Be("-__v");
    }

    [Fact]
    public void Sha256Base64_KnownInput_ProducesExpectedHash()
    {
        var result = Utils.Sha256Base64("hello world");

        result.Should().Be("uU0nuZNNPgilLlLX2n2r-sSE7-N6U4DukIj3rOLvzek");
    }

    [Fact]
    public void Sha256Base64_ProducesWellFormattedResult()
    {
        var input = "hello world";

        var result = Utils.Sha256Base64(input);

        result.Should().NotBeNullOrEmpty();
        result.Should().MatchRegex(@"^[a-zA-Z0-9_-]{43}$"); // Base64-URL with no padding
    }

    [Fact]
    public void Sha256Base64_SameInput_ProducesSameOutput()
    {
        var input = "same input";

        var h1 = Utils.Sha256Base64(input);
        var h2 = Utils.Sha256Base64(input);

        h1.Should().Be(h2);
    }

    [Fact]
    public void Sha256Base64_DifferentInputs_ProduceDifferentHashes()
    {
        var h1 = Utils.Sha256Base64("alpha");
        var h2 = Utils.Sha256Base64("beta");

        h1.Should().NotBe(h2);
    }

    [Fact]
    public void GenerateBase32Secret_ShouldReturnDifferentValues()
    {
        var secret1 = Utils.GenerateBase32Secret();
        var secret2 = Utils.GenerateBase32Secret();
        secret1.Should().NotBe(secret2);
    }

    [Fact]
    public void Base32Encoding_ToBytes_ShouldRoundtrip()
    {
        var input = "NBSWY3DPEB3W64TMMQ"; // "hello world" in Base32
        var result = Utils.Base32Encode(Encoding.UTF8.GetBytes("hello world"));

        result.Should().Be(input);
    }
}