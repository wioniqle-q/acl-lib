using System.Security.Cryptography;
using Acl.Fs.Core.Models.AesGcm;

namespace Acl.Fs.Core.UnitTests.Models.AesGcm;

public sealed class AesDecryptionInputTests
{
    [Fact]
    public void Constructor_WithValidPassword_ShouldCreateInstance()
    {
        var password = "test-password"u8.ToArray();
        var passwordMemory = new ReadOnlyMemory<byte>(password);

        var input = new AesDecryptionInput(passwordMemory);

        Assert.Equal(passwordMemory.ToArray(), input.Password.ToArray());
    }

    [Fact]
    public void Constructor_WithEmptyPassword_ShouldThrowArgumentException()
    {
        var emptyPassword = ReadOnlyMemory<byte>.Empty;

        var exception = Assert.Throws<ArgumentException>(() =>
            new AesDecryptionInput(emptyPassword));

        Assert.Equal("Password cannot be empty. (Parameter 'password')", exception.Message);
        Assert.Equal("password", exception.ParamName);
    }

    [Fact]
    public void Constructor_WithSingleBytePassword_ShouldCreateInstance()
    {
        var password = new byte[] { 0x42 };
        var passwordMemory = new ReadOnlyMemory<byte>(password);

        var input = new AesDecryptionInput(passwordMemory);

        Assert.Single(input.Password.ToArray());
        Assert.Equal(0x42, input.Password.ToArray()[0]);
    }

    [Fact]
    public void Constructor_WithLargePassword_ShouldCreateInstance()
    {
        var password = new byte[1024];
        RandomNumberGenerator.Fill(password);
        var passwordMemory = new ReadOnlyMemory<byte>(password);

        var input = new AesDecryptionInput(passwordMemory);

        Assert.Equal(1024, input.Password.Length);
        Assert.Equal(password, input.Password.ToArray());
    }

    [Fact]
    public void Password_Property_ShouldReturnSameValueAsConstructorInput()
    {
        var originalPassword = "secure-password-123"u8.ToArray();

        var passwordMemory = new ReadOnlyMemory<byte>(originalPassword);
        var input = new AesDecryptionInput(passwordMemory);

        var retrievedPassword = input.Password;

        Assert.Equal(originalPassword, retrievedPassword.ToArray());
        Assert.True(passwordMemory.Span.SequenceEqual(retrievedPassword.Span));
    }

    [Fact]
    public void Constructor_WithNullByteArrayPassword_ShouldThrowArgumentException()
    {
        var passwordMemory = new ReadOnlyMemory<byte>(null);

        var exception = Assert.Throws<ArgumentException>(() =>
            new AesDecryptionInput(passwordMemory));

        Assert.Equal("Password cannot be empty. (Parameter 'password')", exception.Message);
    }

    [Fact]
    public void Constructor_WithZeroLengthArray_ShouldThrowArgumentException()
    {
        var emptyArray = Array.Empty<byte>();
        var passwordMemory = new ReadOnlyMemory<byte>(emptyArray);

        var exception = Assert.Throws<ArgumentException>(() =>
            new AesDecryptionInput(passwordMemory));

        Assert.Equal("Password cannot be empty. (Parameter 'password')", exception.Message);
        Assert.Equal("password", exception.ParamName);
    }

    [Fact]
    public void Equality_WithSamePassword_ShouldBeEqual()
    {
        var password = "test-password"u8.ToArray();
        var passwordMemory1 = new ReadOnlyMemory<byte>(password);
        var passwordMemory2 = new ReadOnlyMemory<byte>(password);

        var input1 = new AesDecryptionInput(passwordMemory1);
        var input2 = new AesDecryptionInput(passwordMemory2);

        Assert.True(input1.Password.Span.SequenceEqual(input2.Password.Span));
    }

    [Fact]
    public void Equality_WithDifferentPassword_ShouldNotBeEqual()
    {
        var password1 = "password1"u8.ToArray();
        var password2 = "password2"u8.ToArray();
        var passwordMemory1 = new ReadOnlyMemory<byte>(password1);
        var passwordMemory2 = new ReadOnlyMemory<byte>(password2);

        var input1 = new AesDecryptionInput(passwordMemory1);
        var input2 = new AesDecryptionInput(passwordMemory2);

        Assert.False(input1.Password.Span.SequenceEqual(input2.Password.Span));
    }

    [Fact]
    public void ToString_ShouldReturnReadableRepresentation()
    {
        var password = "test-password"u8.ToArray();
        var passwordMemory = new ReadOnlyMemory<byte>(password);
        var input = new AesDecryptionInput(passwordMemory);

        var stringRepresentation = input.ToString();

        Assert.NotNull(stringRepresentation);
        Assert.Contains("AesDecryptionInput", stringRepresentation);
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

        var input = new AesDecryptionInput(passwordMemory);

        Assert.Equal(passwordLength, input.Password.Length);
        Assert.Equal(password, input.Password.ToArray());
    }

    [Fact]
    public void Dispose_ShouldZeroMemoryOfPassword()
    {
        var password = "test-password"u8.ToArray();
        var passwordMemory = new ReadOnlyMemory<byte>(password);
        var input = new AesDecryptionInput(passwordMemory);

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
        var input = new AesDecryptionInput(passwordMemory);

        input.Dispose();
        input.Dispose();
        input.Dispose();

        Assert.True(true);
    }
}