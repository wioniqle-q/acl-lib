using System.Security.Cryptography;
using System.Text;
using Acl.Fs.Core.Service.Shared.KeyDerivation;

namespace Acl.Fs.Core.UnitTests.Service.Shared.KeyDerivation;

public sealed class Argon2KeyDerivationServiceTests
{
    private const int OutputLength = 32;
    private readonly Argon2KeyDerivationService _service = new();

    [Fact]
    public void SaltSize_Should_ReturnValidSize()
    {
        var saltSize = _service.SaltSize;

        Assert.True(saltSize > 0);
        Assert.True(saltSize is 16);
    }

    [Fact]
    public void DeriveKey_WithValidInputs_Should_ReturnKeyOfCorrectLength()
    {
        const string password = "testpassword123";

        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var salt = RandomNumberGenerator.GetBytes(_service.SaltSize);

        var derivedKey = _service.DeriveKey(passwordBytes, salt, OutputLength);

        Assert.NotNull(derivedKey);
        Assert.Equal(OutputLength, derivedKey.Length);
    }

    [Fact]
    public void DeriveKey_WithSameInputs_Should_ReturnSameKey()
    {
        const string password = "consistentpassword";

        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var salt = RandomNumberGenerator.GetBytes(_service.SaltSize);

        var key1 = _service.DeriveKey(passwordBytes, salt, OutputLength);
        var key2 = _service.DeriveKey(passwordBytes, salt, OutputLength);

        Assert.Equal(key1, key2);
    }

    [Fact]
    public void DeriveKey_WithDifferentPasswords_Should_ReturnDifferentKeys()
    {
        const string password1 = "password123";
        const string password2 = "password456";

        var passwordBytes1 = Encoding.UTF8.GetBytes(password1);
        var passwordBytes2 = Encoding.UTF8.GetBytes(password2);

        var salt = RandomNumberGenerator.GetBytes(_service.SaltSize);

        var key1 = _service.DeriveKey(passwordBytes1, salt, OutputLength);
        var key2 = _service.DeriveKey(passwordBytes2, salt, OutputLength);

        Assert.NotEqual(key1, key2);
    }

    [Fact]
    public void DeriveKey_WithDifferentSalts_Should_ReturnDifferentKeys()
    {
        const string password = "samepassword";

        var passwordBytes = Encoding.UTF8.GetBytes(password);

        var salt1 = RandomNumberGenerator.GetBytes(_service.SaltSize);
        var salt2 = RandomNumberGenerator.GetBytes(_service.SaltSize);

        var key1 = _service.DeriveKey(passwordBytes, salt1, OutputLength);
        var key2 = _service.DeriveKey(passwordBytes, salt2, OutputLength);

        Assert.NotEqual(key1, key2);
    }

    [Fact]
    public void DeriveKey_WithDifferentOutputLengths_Should_ReturnKeysOfCorrectLengths()
    {
        const string password = "testpassword";

        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var salt = RandomNumberGenerator.GetBytes(_service.SaltSize);

        const int outputLength1 = 16;
        const int outputLength2 = 64;

        var key1 = _service.DeriveKey(passwordBytes, salt, outputLength1);
        var key2 = _service.DeriveKey(passwordBytes, salt, outputLength2);

        Assert.Equal(outputLength1, key1.Length);
        Assert.Equal(outputLength2, key2.Length);
        Assert.NotEqual(key1.Length, key2.Length);
    }

    [Fact]
    public void DeriveKey_WithEmptyPassword_Should_DeriveKey()
    {
        var passwordBytes = Array.Empty<byte>();
        var salt = RandomNumberGenerator.GetBytes(_service.SaltSize);

        var derivedKey = _service.DeriveKey(passwordBytes, salt, OutputLength);

        Assert.NotNull(derivedKey);
        Assert.Equal(OutputLength, derivedKey.Length);
        Assert.Contains(derivedKey, b => b is not 0);
    }

    [Fact]
    public void DeriveKey_WithMinimalSalt_Should_DeriveKey()
    {
        const string password = "testpassword";

        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var salt = RandomNumberGenerator.GetBytes(1);

        var derivedKey = _service.DeriveKey(passwordBytes, salt, OutputLength);

        Assert.NotNull(derivedKey);
        Assert.Equal(OutputLength, derivedKey.Length);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(128)]
    public void DeriveKey_WithVariousOutputLengths_Should_ReturnCorrectLength(int outputLength)
    {
        const string password = "testpassword";

        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var salt = RandomNumberGenerator.GetBytes(_service.SaltSize);

        var derivedKey = _service.DeriveKey(passwordBytes, salt, outputLength);
        Assert.Equal(outputLength, derivedKey.Length);
    }

    [Fact]
    public void DeriveKey_WithUnicodePassword_Should_DeriveKey()
    {
        const string password =
            @"\u0074\u0068\u0069\u0073\u0020\u0069\u0073\u0020\u0061\u006e\u0020\u0061\u0072\u0067\u006f\u006e\u0032\u0020\u0074\u0065\u0073\u0074\u0020\u0075\u006e\u0069\u0063\u006f\u0064\u0065\u0020\u0074\u0065\u0078\u0074";

        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var salt = RandomNumberGenerator.GetBytes(_service.SaltSize);

        var derivedKey = _service.DeriveKey(passwordBytes, salt, OutputLength);

        Assert.NotNull(derivedKey);
        Assert.Equal(OutputLength, derivedKey.Length);
    }

    [Fact]
    public void DeriveKey_WithLongPassword_Should_DeriveKey()
    {
        var password = new string('a', 1000);

        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var salt = RandomNumberGenerator.GetBytes(_service.SaltSize);

        var derivedKey = _service.DeriveKey(passwordBytes, salt, OutputLength);

        Assert.NotNull(derivedKey);
        Assert.Equal(OutputLength, derivedKey.Length);
    }
}