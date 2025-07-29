using Acl.Fs.Core.Service.Decryption.Shared.Validation;

namespace Acl.Fs.Core.UnitTests.Service.Decryption.Shared.Validation;

public sealed class BlockValidatorTests
{
    [Theory]
    [InlineData(0, 100, 50, "Test: ", 50)]
    [InlineData(50, 100, 60, "Test: ", 100)]
    [InlineData(100, 100, 0, "Test: ", 100)]
    [InlineData(90, 100, 20, "Test: ", 100)]
    public void ValidateAndCalculateBytes_ValidParameters_ReturnsCorrectProcessedBytes(
        long processedBytes, long originalSize, int bytesRead, string prefix, long expected)
    {
        var validator = new BlockValidator();

        var result = validator.ValidateAndCalculateBytes(processedBytes, originalSize, bytesRead, prefix);

        Assert.Equal(expected, result);
    }

    [Fact]
    public void ValidateAndCalculateBytes_WhenProcessedBytesExceedsOriginalSize_ThrowsException()
    {
        var validator = new BlockValidator();
        const long processedBytes = 101;
        const long originalSize = 100;
        const int bytesRead = 0;
        const string prefix = "Test: ";

        var ex = Assert.Throws<InvalidOperationException>(() =>
            validator.ValidateAndCalculateBytes(processedBytes, originalSize, bytesRead, prefix));

        Assert.Contains($"Test: Processed bytes ({processedBytes}) exceeded the", ex.Message);
    }

    [Fact]
    public void ValidateAndCalculateBytes_WhenBytesReadIsNegative_ThrowsException()
    {
        const long processedBytes = 0;
        const long originalSize = 100;
        const int bytesRead = -1;
        const string prefix = "Test: ";

        var validator = new BlockValidator();

        var ex = Assert.Throws<InvalidOperationException>(() =>
            validator.ValidateAndCalculateBytes(processedBytes, originalSize, bytesRead, prefix));
        Assert.Contains("Test: Negative bytesToWrite value detected", ex.Message);
    }

    [Fact]
    public void ValidateBlockWriteParameters_ValidParameters_DoesNotThrow()
    {
        const int bytesRead = 50;
        const long originalSize = 100;
        const long processedBytes = 0;
        const int blockSize = 50;
        const int plaintextLength = 50;

        var validator = new BlockValidator();

        validator.ValidateBlockWriteParameters(bytesRead, originalSize, processedBytes, blockSize, plaintextLength);
    }

    [Fact]
    public void ValidateBlockWriteParameters_WhenBlockSizeExceedsPlaintextLength_ThrowsException()
    {
        const int bytesRead = 50;
        const long originalSize = 100;
        const long processedBytes = 0;
        const int blockSize = 60;
        const int plaintextLength = 50;

        var validator = new BlockValidator();

        var ex = Assert.Throws<InvalidOperationException>(() =>
            validator.ValidateBlockWriteParameters(bytesRead, originalSize, processedBytes, blockSize,
                plaintextLength));

        Assert.Contains(
            $"Block size ({blockSize}) exceeds plaintext buffer length ({plaintextLength}). Data corruption or logic error.",
            ex.Message);
    }

    [Fact]
    public void ValidateBlockWriteParameters_WhenProcessedBytesExceedsOriginalSize_ThrowsException()
    {
        const int bytesRead = 0;
        const long originalSize = 100;
        const long processedBytes = 101;
        const int blockSize = 50;
        const int plaintextLength = 50;

        var validator = new BlockValidator();

        var ex = Assert.Throws<InvalidOperationException>(() =>
            validator.ValidateBlockWriteParameters(bytesRead, originalSize, processedBytes, blockSize,
                plaintextLength));

        Assert.Contains("Negative bytesToWrite value detected: -1. Data corruption or logic error.", ex.Message);
    }

    [Fact]
    public void ValidateBlockWriteParameters_WhenBytesReadIsNegative_ThrowsException()
    {
        const int bytesRead = -1;
        const long originalSize = 100;
        const long processedBytes = 0;
        const int blockSize = 50;
        const int plaintextLength = 50;

        var validator = new BlockValidator();

        var ex = Assert.Throws<InvalidOperationException>(() =>
            validator.ValidateBlockWriteParameters(bytesRead, originalSize, processedBytes, blockSize,
                plaintextLength));

        Assert.Contains("Negative bytesToWrite value detected: -1. Data corruption or logic error.", ex.Message);
    }
}