using Acl.Fs.Constant.Versioning;
using Acl.Fs.Core.Abstractions;
using Acl.Fs.Core.Policy;

namespace Acl.Fs.Core.UnitTests.Policy;

public sealed class AlignedPolicyTests
{
    private readonly AlignedPolicy _alignedPolicy = new();

    [Theory]
    [InlineData(100, false, 100)]
    [InlineData(256, false, 256)]
    [InlineData(512, false, 512)]
    [InlineData(1024, false, 1024)]
    public void CalculateProcessingSize_WhenNotLastBlock_ShouldReturnOriginalSize(
        int bytesRead, bool isLastBlock, int expectedSize)
    {
        var result = _alignedPolicy.CalculateProcessingSize(bytesRead, isLastBlock);

        Assert.Equal(expectedSize, result);
    }

    [Theory]
    [InlineData(100, true, 512)]
    [InlineData(256, true, 512)]
    [InlineData(512, true, 512)]
    [InlineData(513, true, 1024)]
    [InlineData(1000, true, 1024)]
    [InlineData(1024, true, 1024)]
    [InlineData(1, true, 512)]
    public void CalculateProcessingSize_WhenLastBlock_ShouldReturnAlignedSize(
        int bytesRead, bool isLastBlock, int expectedSize)
    {
        var result = _alignedPolicy.CalculateProcessingSize(bytesRead, isLastBlock);

        Assert.Equal(expectedSize, result);
    }

    [Fact]
    public void CalculateProcessingSize_LastBlockAlignment_ShouldFollowSectorBoundary()
    {
        var testCases = new[]
        {
            (input: 511, expected: 512),
            (input: 512, expected: 512),
            (input: 513, expected: 1024),
            (input: 1023, expected: 1024),
            (input: 1024, expected: 1024),
            (input: 1025, expected: 1536)
        };

        foreach (var (input, expected) in testCases)
        {
            var result = _alignedPolicy.CalculateProcessingSize(input, true);

            Assert.Equal(expected, result);
        }
    }

    [Theory]
    [InlineData(0, false, 0)]
    [InlineData(0, true, 0)]
    public void CalculateProcessingSize_ZeroBytes_ShouldReturnZero(
        int bytesRead, bool isLastBlock, int expectedSize)
    {
        var result = _alignedPolicy.CalculateProcessingSize(bytesRead, isLastBlock);

        Assert.Equal(expectedSize, result);
    }

    [Fact]
    public void GetMetadataBufferSize_ShouldReturnHeaderSize()
    {
        var result = _alignedPolicy.GetMetadataBufferSize();

        Assert.Equal(VersionConstants.HeaderSize, result);
        Assert.True(result > 0, "Header size should be positive");
        Assert.True(result % 512 == 0, "Header size should be sector-aligned");
    }

    [Fact]
    public void GetMetadataBufferSize_ShouldBeSectorAligned()
    {
        var result = _alignedPolicy.GetMetadataBufferSize();

        Assert.Equal(0, result % 512);
    }

    [Fact]
    public void GetFileOptions_ShouldReturnSectorAlignedOptions()
    {
        var result = _alignedPolicy.GetFileOptions();

        Assert.True(result.HasFlag(FileOptions.Asynchronous),
            "Should include Asynchronous flag for async I/O operations");
        Assert.True(result.HasFlag(FileOptions.SequentialScan),
            "Should include SequentialScan flag for sequential access pattern");
        Assert.True(result.HasFlag(FileOptions.WriteThrough),
            "Should include WriteThrough flag for immediate disk writes");
        Assert.True(result.HasFlag((FileOptions)0x20000000),
            "Should include sector alignment flag for direct I/O");
    }

    [Fact]
    public void GetFileOptions_ShouldHaveCorrectFlagCombination()
    {
        const FileOptions expectedOptions = FileOptions.Asynchronous |
                                            FileOptions.SequentialScan |
                                            FileOptions.WriteThrough |
                                            (FileOptions)0x20000000;

        var result = _alignedPolicy.GetFileOptions();

        Assert.Equal(expectedOptions, result);
    }

    [Fact]
    public void AlignedPolicy_ShouldImplementIAlignmentPolicy()
    {
        Assert.IsType<IAlignmentPolicy>(_alignedPolicy, false);
    }

    [Theory]
    [InlineData(1024)]
    [InlineData(4096)]
    [InlineData(8192)]
    [InlineData(16384)]
    public void CalculateProcessingSize_LargeBuffers_ShouldHandleCorrectly(int bufferSize)
    {
        var nonLastResult = _alignedPolicy.CalculateProcessingSize(bufferSize, false);
        var lastResult = _alignedPolicy.CalculateProcessingSize(bufferSize, true);

        Assert.Equal(bufferSize, nonLastResult);
        Assert.Equal(bufferSize, lastResult);
        Assert.True(lastResult % 512 == 0, "Last block should be sector-aligned");
    }
}