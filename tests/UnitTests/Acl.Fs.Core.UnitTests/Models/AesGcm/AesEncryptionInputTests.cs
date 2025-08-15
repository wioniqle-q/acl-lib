using System.Security.Cryptography;
using System.Text;
using Acl.Fs.Core.Models.AesGcm;

namespace Acl.Fs.Core.UnitTests.Models.AesGcm;

public sealed class AesEncryptionInputTests
{
    [Fact]
    public void Constructor_WithValidPassword_ShouldCreateInstance()
    {
        var password = "test-password"u8.ToArray();
        var passwordMemory = new ReadOnlyMemory<byte>(password);

        var input = new AesEncryptionInput(passwordMemory);

        Assert.Equal(passwordMemory.ToArray(), input.Password.ToArray());
    }

    [Fact]
    public void Constructor_WithEmptyPassword_ShouldThrowArgumentException()
    {
        var emptyPassword = ReadOnlyMemory<byte>.Empty;

        var exception = Assert.Throws<ArgumentException>(() =>
            new AesEncryptionInput(emptyPassword));

        Assert.Equal("Password cannot be empty. (Parameter 'password')", exception.Message);
        Assert.Equal("password", exception.ParamName);
    }

    [Fact]
    public void Constructor_WithSingleBytePassword_ShouldCreateInstance()
    {
        var password = new byte[] { 0x42 };
        var passwordMemory = new ReadOnlyMemory<byte>(password);

        var input = new AesEncryptionInput(passwordMemory);

        Assert.Single(input.Password.ToArray());
        Assert.Equal(0x42, input.Password.ToArray()[0]);
    }

    [Fact]
    public void Constructor_WithLargePassword_ShouldCreateInstance()
    {
        var password = new byte[1024];
        RandomNumberGenerator.Fill(password);

        var passwordMemory = new ReadOnlyMemory<byte>(password);

        var input = new AesEncryptionInput(passwordMemory);

        Assert.Equal(1024, input.Password.Length);
        Assert.Equal(password, input.Password.ToArray());
    }

    [Fact]
    public void Password_Property_ShouldReturnSameValueAsConstructorInput()
    {
        var originalPassword = "secure-password-123"u8.ToArray();

        var passwordMemory = new ReadOnlyMemory<byte>(originalPassword);
        var input = new AesEncryptionInput(passwordMemory);

        var retrievedPassword = input.Password;

        Assert.Equal(originalPassword, retrievedPassword.ToArray());
        Assert.True(passwordMemory.Span.SequenceEqual(retrievedPassword.Span));
    }

    [Fact]
    public void Constructor_WithNullByteArrayPassword_ShouldThrowArgumentException()
    {
        var passwordMemory = new ReadOnlyMemory<byte>(null);

        var exception = Assert.Throws<ArgumentException>(() =>
            new AesEncryptionInput(passwordMemory));

        Assert.Equal("Password cannot be empty. (Parameter 'password')", exception.Message);
    }

    [Fact]
    public void Constructor_WithZeroLengthArray_ShouldThrowArgumentException()
    {
        var emptyArray = Array.Empty<byte>();
        var passwordMemory = new ReadOnlyMemory<byte>(emptyArray);

        var exception = Assert.Throws<ArgumentException>(() =>
            new AesEncryptionInput(passwordMemory));

        Assert.Equal("Password cannot be empty. (Parameter 'password')", exception.Message);
        Assert.Equal("password", exception.ParamName);
    }

    [Fact]
    public void Equality_WithSamePassword_ShouldBeEqual()
    {
        var password = "test-password"u8.ToArray();
        var passwordMemory1 = new ReadOnlyMemory<byte>(password);
        var passwordMemory2 = new ReadOnlyMemory<byte>(password);

        var input1 = new AesEncryptionInput(passwordMemory1);
        var input2 = new AesEncryptionInput(passwordMemory2);

        Assert.True(input1.Password.Span.SequenceEqual(input2.Password.Span));
    }

    [Fact]
    public void Equality_WithDifferentPassword_ShouldNotBeEqual()
    {
        var password1 = "password1"u8.ToArray();
        var password2 = "password2"u8.ToArray();

        var passwordMemory1 = new ReadOnlyMemory<byte>(password1);
        var passwordMemory2 = new ReadOnlyMemory<byte>(password2);

        var input1 = new AesEncryptionInput(passwordMemory1);
        var input2 = new AesEncryptionInput(passwordMemory2);

        Assert.False(input1.Password.Span.SequenceEqual(input2.Password.Span));
    }

    [Fact]
    public void ToString_ShouldReturnReadableRepresentation()
    {
        var password = "test-password"u8.ToArray();
        var passwordMemory = new ReadOnlyMemory<byte>(password);
        var input = new AesEncryptionInput(passwordMemory);

        var stringRepresentation = input.ToString();

        Assert.NotNull(stringRepresentation);
        Assert.Contains("AesEncryptionInput", stringRepresentation);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(128)]
    [InlineData(256)]
    [InlineData(512)]
    public void Constructor_WithVariousPasswordLengths_ShouldCreateInstance(int passwordLength)
    {
        var password = new byte[passwordLength];
        RandomNumberGenerator.Fill(password);
        var passwordMemory = new ReadOnlyMemory<byte>(password);

        var input = new AesEncryptionInput(passwordMemory);

        Assert.Equal(passwordLength, input.Password.Length);
        Assert.Equal(password, input.Password.ToArray());
    }

    [Fact]
    public void Constructor_WithSpecialCharacterPassword_ShouldCreateInstance()
    {
        var passwordString = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~";

        var password = Encoding.UTF8.GetBytes(passwordString);
        var passwordMemory = new ReadOnlyMemory<byte>(password);

        var input = new AesEncryptionInput(passwordMemory);

        Assert.Equal(password, input.Password.ToArray());
    }

    [Fact]
    public void Constructor_WithBinaryPassword_ShouldCreateInstance()
    {
        var password = new byte[] { 0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE };
        var passwordMemory = new ReadOnlyMemory<byte>(password);

        var input = new AesEncryptionInput(passwordMemory);

        Assert.Equal(password, input.Password.ToArray());
        Assert.Equal(6, input.Password.Length);
    }

    [Fact]
    public void Equality_WithNullReference_ShouldNotThrow()
    {
        var password = "test-password"u8.ToArray();

        var passwordMemory = new ReadOnlyMemory<byte>(password);
        var input = new AesEncryptionInput(passwordMemory);

        Assert.False(input.Equals(null));
    }

    [Fact]
    public void Dispose_ShouldZeroMemoryOfPassword()
    {
        var password = "test-password"u8.ToArray();
        var passwordMemory = new ReadOnlyMemory<byte>(password);
        var input = new AesEncryptionInput(passwordMemory);

        Assert.Equal(password, input.Password.ToArray());

        input.Dispose();

        var passwordAfterDispose = input.Password.ToArray();
        Assert.All(passwordAfterDispose, b => Assert.Equal(0, b));
    }

    [Fact]
    public void Dispose_CalledMultipleTimes_ShouldNotThrow()
    {
        var password = "test-password"u8.ToArray();
        var passwordMemory = new ReadOnlyMemory<byte>(password);
        var input = new AesEncryptionInput(passwordMemory);
        input.Dispose();
        input.Dispose();
        input.Dispose();

        Assert.True(true);
    }
}