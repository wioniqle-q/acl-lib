using Acl.Fs.Constant.Versioning;
using Acl.Fs.Core.Policy;

namespace Acl.Fs.Core.UnitTests.Policy;

public sealed class UnalignedPolicyTests
{
    private readonly UnalignedPolicy _unalignedPolicy = new();

    [Theory]
    [InlineData(100, false, 100)]
    [InlineData(256, false, 256)]
    [InlineData(512, false, 512)]
    [InlineData(1024, false, 1024)]
    public void CalculateProcessingSize_WhenNotLastBlock_ShouldReturnOriginalSize(
        int bytesRead, bool isLastBlock, int expectedSize)
    {
        var result = _unalignedPolicy.CalculateProcessingSize(bytesRead, isLastBlock);

        Assert.Equal(expectedSize, result);
    }

    [Theory]
    [InlineData(100, true, 100)]
    [InlineData(256, true, 256)]
    [InlineData(512, true, 512)]
    [InlineData(513, true, 513)]
    [InlineData(1000, true, 1000)]
    [InlineData(1024, true, 1024)]
    [InlineData(1, true, 1)]
    public void CalculateProcessingSize_WhenLastBlock_ShouldReturnOriginalSize(
        int bytesRead, bool isLastBlock, int expectedSize)
    {
        var result = _unalignedPolicy.CalculateProcessingSize(bytesRead, isLastBlock);

        Assert.Equal(expectedSize, result);
    }

    [Fact]
    public void CalculateProcessingSize_ShouldIgnoreLastBlockFlag()
    {
        const int testSize = 777;

        var lastBlockResult = _unalignedPolicy.CalculateProcessingSize(testSize, true);
        var nonLastBlockResult = _unalignedPolicy.CalculateProcessingSize(testSize, false);

        Assert.Equal(testSize, lastBlockResult);
        Assert.Equal(testSize, nonLastBlockResult);
        Assert.Equal(lastBlockResult, nonLastBlockResult);
    }

    [Fact]
    public void GetMetadataBufferSize_ShouldReturnUnalignedHeaderSize()
    {
        var result = _unalignedPolicy.GetMetadataBufferSize();

        Assert.Equal(VersionConstants.UnalignedHeaderSize, result);
        Assert.True(result > 0, "Header size should be positive");
    }

    [Fact]
    public void GetFileOptions_ShouldReturnNonSectorAlignedOptions()
    {
        var result = _unalignedPolicy.GetFileOptions();

        Assert.True(result.HasFlag(FileOptions.Asynchronous),
            "Should include Asynchronous flag for async I/O operations");
        Assert.True(result.HasFlag(FileOptions.SequentialScan),
            "Should include SequentialScan flag for sequential access pattern");
        Assert.True(result.HasFlag(FileOptions.WriteThrough),
            "Should include WriteThrough flag for immediate disk writes");
        Assert.False(result.HasFlag((FileOptions)0x20000000),
            "Should NOT include sector alignment flag for standard I/O");
    }

    [Fact]
    public void GetFileOptions_ShouldHaveCorrectFlagCombination()
    {
        const FileOptions expectedOptions = FileOptions.Asynchronous |
                                            FileOptions.SequentialScan |
                                            FileOptions.WriteThrough;

        var result = _unalignedPolicy.GetFileOptions();

        Assert.Equal(expectedOptions, result);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(511)]
    [InlineData(513)]
    [InlineData(1023)]
    [InlineData(1025)]
    public void CalculateProcessingSize_NonSectorAlignedSizes_ShouldRemainUnchanged(int size)
    {
        var result = _unalignedPolicy.CalculateProcessingSize(size, true);

        Assert.Equal(size, result);
    }
}