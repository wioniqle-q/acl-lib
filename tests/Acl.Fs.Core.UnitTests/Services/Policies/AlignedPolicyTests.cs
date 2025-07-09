using Acl.Fs.Core.Services.Policies;
using static Acl.Fs.Abstractions.Constants.StorageConstants;

namespace Acl.Fs.Core.UnitTests.Services.Policies;

public sealed class AlignedPolicyTests
{
    private readonly AlignedPolicy _alignedPolicy = new();

    [Fact]
    public void CalculateProcessingSize_NotLastBlock_ReturnsOriginalSize()
    {
        const int bytesRead = 300;
        const bool isLastBlock = false;

        var result = _alignedPolicy.CalculateProcessingSize(bytesRead, isLastBlock);

        Assert.Equal(300, result);
    }

    [Fact]
    public void CalculateProcessingSize_LastBlock_ReturnsAlignedSize()
    {
        const int bytesRead = 300;
        const bool isLastBlock = true;

        var result = _alignedPolicy.CalculateProcessingSize(bytesRead, isLastBlock);

        Assert.Equal(512, result);
    }

    [Fact]
    public void CalculateProcessingSize_LastBlockAlreadyAligned_ReturnsOriginalSize()
    {
        const int bytesRead = 512;
        const bool isLastBlock = true;

        var result = _alignedPolicy.CalculateProcessingSize(bytesRead, isLastBlock);

        Assert.Equal(512, result);
    }

    [Theory]
    [InlineData(1, true, 512)]
    [InlineData(100, true, 512)]
    [InlineData(511, true, 512)]
    [InlineData(512, true, 512)]
    [InlineData(513, true, 1024)]
    [InlineData(1000, false, 1000)]
    [InlineData(1024, false, 1024)]
    [InlineData(1025, false, 1025)]
    public void CalculateProcessingSize_VariousInputs_ReturnsCorrectResult(int bytesRead, bool isLastBlock,
        int expected)
    {
        var result = _alignedPolicy.CalculateProcessingSize(bytesRead, isLastBlock);

        Assert.Equal(expected, result);
    }

    [Fact]
    public void GetMetadataBufferSize_ReturnsStorageConstantSectorSize()
    {
        var result = _alignedPolicy.GetMetadataBufferSize();

        Assert.Equal(SectorSize, result);
    }

    [Fact]
    public void GetFileOptions_ReturnsAlignedFileOptions()
    {
        var result = _alignedPolicy.GetFileOptions();

        const FileOptions expectedOptions = FileOptions.Asynchronous |
                                            FileOptions.SequentialScan |
                                            FileOptions.WriteThrough |
                                            (FileOptions)0x20000000;

        Assert.Equal(expectedOptions, result);
    }

    [Fact]
    public void GetFileOptions_IncludesSectorAlignedFlag()
    {
        var result = _alignedPolicy.GetFileOptions();

        Assert.True(result.HasFlag((FileOptions)0x20000000));
    }

    [Fact]
    public void GetFileOptions_IncludesAsynchronousFlag()
    {
        var result = _alignedPolicy.GetFileOptions();

        Assert.True(result.HasFlag(FileOptions.Asynchronous));
    }

    [Fact]
    public void GetFileOptions_IncludesSequentialScanFlag()
    {
        var result = _alignedPolicy.GetFileOptions();

        Assert.True(result.HasFlag(FileOptions.SequentialScan));
    }

    [Fact]
    public void GetFileOptions_IncludesWriteThroughFlag()
    {
        var result = _alignedPolicy.GetFileOptions();

        Assert.True(result.HasFlag(FileOptions.WriteThrough));
    }
}