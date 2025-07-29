using Acl.Fs.Core.Service.Decryption.Shared.Block;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;
using static Acl.Fs.Constant.Storage.StorageConstants;

namespace Acl.Fs.Core.UnitTests.Service.Decryption.Shared.Block;

public sealed class BlockCalculatorTests
{
    private const int
        StandardHeaderSize =
            2 + 12 + 8 + 32 + 16; // VersionHeaderSize + NonceSize + sizeof(long) + SaltSize + Argon2IdSaltSize

    private const int
        XChaCha20Poly1305HeaderSize =
            2 + 24 + 8 + 32 +
            16; // VersionHeaderSize + XChaCha20Poly1305NonceSize + sizeof(long) + SaltSize + Argon2IdSaltSize

    [Theory]
    [InlineData(0, SectorSize, BufferSize, 0)] // Empty stream
    [InlineData(SectorSize, SectorSize, BufferSize, 0)] // Only header, no blocks
    [InlineData(SectorSize + SectorSize + BufferSize, SectorSize, BufferSize, 1)] // Header + 1 block
    [InlineData(SectorSize + SectorSize + BufferSize + 1, SectorSize, BufferSize, 2)] // Header + 1 block + 1 extra byte
    [InlineData(SectorSize + 2 * (SectorSize + BufferSize), SectorSize, BufferSize, 2)] // Header + 2 blocks
    public void CalculateTotalBlocks_SectorAligned_ReturnsCorrectBlockCount(long encryptedStreamLength,
        int metadataBufferSize, int bufferSize, long expectedBlocks)
    {
        var result = BlockCalculator.CalculateTotalBlocks(encryptedStreamLength, metadataBufferSize, bufferSize);

        Assert.Equal(expectedBlocks, result);
    }

    [Theory]
    [InlineData(0, StandardHeaderSize, BufferSize, 0)] // Empty stream
    [InlineData(StandardHeaderSize, StandardHeaderSize, BufferSize, 0)] // Only header, no blocks
    [InlineData(StandardHeaderSize + TagSize + BufferSize, StandardHeaderSize, BufferSize, 1)] // Header + 1 block
    [InlineData(StandardHeaderSize + TagSize + BufferSize + 1, StandardHeaderSize, BufferSize,
        2)] // Header + 1 block + 1 extra byte
    [InlineData(StandardHeaderSize + 2 * (TagSize + BufferSize), StandardHeaderSize, BufferSize,
        2)] // Header + 2 blocks
    public void CalculateTotalBlocks_Unaligned_ReturnsCorrectBlockCount(long encryptedStreamLength,
        int metadataBufferSize, int bufferSize, long expectedBlocks)
    {
        var result = BlockCalculator.CalculateTotalBlocks(encryptedStreamLength, metadataBufferSize, bufferSize);

        Assert.Equal(expectedBlocks, result);
    }

    [Theory]
    [InlineData(XChaCha20Poly1305HeaderSize, XChaCha20Poly1305HeaderSize, BufferSize,
        0)] // XChaCha20Poly1305 header only
    [InlineData(XChaCha20Poly1305HeaderSize + TagSize + BufferSize, XChaCha20Poly1305HeaderSize, BufferSize,
        1)] // XChaCha20Poly1305 header + 1 block
    [InlineData(XChaCha20Poly1305HeaderSize + 2 * (TagSize + BufferSize), XChaCha20Poly1305HeaderSize, BufferSize,
        2)] // XChaCha20Poly1305 header + 2 blocks
    public void CalculateTotalBlocks_XChaCha20Poly1305_ReturnsCorrectBlockCount(long encryptedStreamLength,
        int metadataBufferSize, int bufferSize, long expectedBlocks)
    {
        var result = BlockCalculator.CalculateTotalBlocks(encryptedStreamLength, metadataBufferSize, bufferSize);

        Assert.Equal(expectedBlocks, result);
    }

    [Fact]
    public void CalculateTotalBlocks_WhenDataLengthIsZero_ShouldReturnZero()
    {
        const int metadataBufferSize = 100;
        const long encryptedStreamLength = 100; // Same as metadata buffer size

        var result = BlockCalculator.CalculateTotalBlocks(encryptedStreamLength, metadataBufferSize, BufferSize);

        Assert.Equal(0, result);
    }

    [Fact]
    public void CalculateTotalBlocks_WhenDataLengthIsNegative_ShouldReturnZero()
    {
        const int metadataBufferSize = 100;
        const long encryptedStreamLength = 50; // Less than metadata buffer size

        var result = BlockCalculator.CalculateTotalBlocks(encryptedStreamLength, metadataBufferSize, BufferSize);

        Assert.Equal(0, result);
    }
}

public sealed class CalculateBytesToWriteTests
{
    [Fact]
    public void CalculateBytesToWrite_WhenBytesReadIsLessThanRemaining_ShouldReturnBytesRead()
    {
        const int bytesRead = 1000;
        const long originalSize = 5000;
        const long processedBytes = 2000;

        var result = BlockCalculator.CalculateBytesToWrite(bytesRead, originalSize, processedBytes);

        Assert.Equal(bytesRead, result);
    }

    [Fact]
    public void CalculateBytesToWrite_WhenBytesReadIsGreaterThanRemaining_ShouldReturnRemainingBytes()
    {
        const int bytesRead = 3000;
        const long originalSize = 5000;
        const long processedBytes = 3500;

        var result = BlockCalculator.CalculateBytesToWrite(bytesRead, originalSize, processedBytes);

        Assert.Equal(1500, result);
    }

    [Fact]
    public void CalculateBytesToWrite_WhenBytesReadEqualsRemaining_ShouldReturnBytesRead()
    {
        const int bytesRead = 1500;
        const long originalSize = 5000;
        const long processedBytes = 3500;

        var result = BlockCalculator.CalculateBytesToWrite(bytesRead, originalSize, processedBytes);

        Assert.Equal(bytesRead, result);
    }

    [Fact]
    public void CalculateBytesToWrite_WhenNoRemainingBytes_ShouldReturnZero()
    {
        const int bytesRead = 1000;
        const long originalSize = 5000;
        const long processedBytes = 5000;

        var result = BlockCalculator.CalculateBytesToWrite(bytesRead, originalSize, processedBytes);

        Assert.Equal(0, result);
    }

    [Theory]
    [InlineData(0, 1000, 0)]
    [InlineData(1000, 1000, 0)]
    [InlineData(500, 1000, 250)]
    [InlineData(1000, 1000, 999)]
    public void CalculateBytesToWrite_WithVariousScenarios_ShouldReturnCorrectValues(int bytesRead,
        long originalSize, long processedBytes)
    {
        var result = BlockCalculator.CalculateBytesToWrite(bytesRead, originalSize, processedBytes);

        var expected = (int)Math.Min(bytesRead, originalSize - processedBytes);
        Assert.Equal(expected, result);
    }
}

public sealed class IsLastBlockTests
{
    [Fact]
    public void IsLastBlock_WhenProcessedPlusBytesReadEqualsOriginalSize_ShouldReturnTrue()
    {
        const long processedBytes = 4000;
        const int bytesRead = 1000;
        const long originalSize = 5000;

        var result = BlockCalculator.IsLastBlock(processedBytes, bytesRead, originalSize);

        Assert.True(result);
    }

    [Fact]
    public void IsLastBlock_WhenProcessedPlusBytesReadExceedsOriginalSize_ShouldReturnTrue()
    {
        const long processedBytes = 4000;
        const int bytesRead = 1500;
        const long originalSize = 5000;

        var result = BlockCalculator.IsLastBlock(processedBytes, bytesRead, originalSize);

        Assert.True(result);
    }

    [Fact]
    public void IsLastBlock_WhenProcessedPlusBytesReadIsLessThanOriginalSize_ShouldReturnFalse()
    {
        const long processedBytes = 3000;
        const int bytesRead = 1000;
        const long originalSize = 5000;

        var result = BlockCalculator.IsLastBlock(processedBytes, bytesRead, originalSize);

        Assert.False(result);
    }

    [Fact]
    public void IsLastBlock_WhenProcessingFirstBlock_ShouldReturnFalseForNormalFile()
    {
        const long processedBytes = 0;
        const int bytesRead = 1000;
        const long originalSize = 5000;

        var result = BlockCalculator.IsLastBlock(processedBytes, bytesRead, originalSize);

        Assert.False(result);
    }

    [Fact]
    public void IsLastBlock_WhenProcessingSmallFile_ShouldReturnTrueIfEntireFileIsRead()
    {
        const long processedBytes = 0;
        const int bytesRead = 500;
        const long originalSize = 500;

        var result = BlockCalculator.IsLastBlock(processedBytes, bytesRead, originalSize);

        Assert.True(result);
    }

    [Theory]
    [InlineData(0, 1000, 1000)]
    [InlineData(4000, 1000, 5000)]
    [InlineData(4500, 600, 5000)]
    [InlineData(2000, 1000, 5000)]
    [InlineData(0, 500, 5000)]
    public void IsLastBlock_WithVariousScenarios_ShouldReturnCorrectResult(long processedBytes, int bytesRead,
        long originalSize)
    {
        var result = BlockCalculator.IsLastBlock(processedBytes, bytesRead, originalSize);

        var expected = processedBytes + bytesRead >= originalSize;
        Assert.Equal(expected, result);
    }
}