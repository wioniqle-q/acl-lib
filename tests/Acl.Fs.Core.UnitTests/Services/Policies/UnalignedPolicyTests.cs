using Acl.Fs.Abstractions.Constants;
using Acl.Fs.Core.Policies;
using static Acl.Fs.Abstractions.Constants.KeyVaultConstants;

namespace Acl.Fs.Core.UnitTests.Services.Policies;

public sealed class UnalignedPolicyTests
{
    private readonly UnalignedPolicy _unalignedPolicy = new();

    [Theory]
    [InlineData(1)]
    [InlineData(100)]
    [InlineData(511)]
    [InlineData(512)]
    [InlineData(1000)]
    [InlineData(1024)]
    [InlineData(2048)]
    public void CalculateProcessingSize_AnyInput_ReturnsOriginalSize(int bytesRead)
    {
        var resultTrue = _unalignedPolicy.CalculateProcessingSize(bytesRead, true);
        var resultFalse = _unalignedPolicy.CalculateProcessingSize(bytesRead, false);

        Assert.Equal(bytesRead, resultTrue);
        Assert.Equal(bytesRead, resultFalse);
    }

    [Fact]
    public void CalculateProcessingSize_LastBlockTrue_ReturnsOriginalSize()
    {
        const int bytesRead = 300;
        const bool isLastBlock = true;

        var result = _unalignedPolicy.CalculateProcessingSize(bytesRead, isLastBlock);

        Assert.Equal(300, result);
    }

    [Fact]
    public void CalculateProcessingSize_LastBlockFalse_ReturnsOriginalSize()
    {
        const int bytesRead = 300;
        const bool isLastBlock = false;

        var result = _unalignedPolicy.CalculateProcessingSize(bytesRead, isLastBlock);

        Assert.Equal(300, result);
    }

    [Fact]
    public void GetMetadataBufferSize_ReturnsExpectedSize()
    {
        var result = _unalignedPolicy.GetMetadataBufferSize();

        var expectedSize = VersionConstants.VersionHeaderSize + NonceSize + sizeof(long) + SaltSize;

        Assert.Equal(expectedSize, result);
    }

    [Fact]
    public void GetMetadataBufferSize_IsConstant()
    {
        var result1 = _unalignedPolicy.GetMetadataBufferSize();
        var result2 = _unalignedPolicy.GetMetadataBufferSize();

        Assert.Equal(result1, result2);
    }

    [Fact]
    public void GetFileOptions_ReturnsUnalignedFileOptions()
    {
        var result = _unalignedPolicy.GetFileOptions();

        const FileOptions expectedOptions = FileOptions.Asynchronous |
                                            FileOptions.SequentialScan |
                                            FileOptions.WriteThrough;

        Assert.Equal(expectedOptions, result);
    }

    [Fact]
    public void GetFileOptions_DoesNotIncludeSectorAlignedFlag()
    {
        var result = _unalignedPolicy.GetFileOptions();

        Assert.False(result.HasFlag((FileOptions)0x20000000));
    }

    [Fact]
    public void GetFileOptions_IncludesAsynchronousFlag()
    {
        var result = _unalignedPolicy.GetFileOptions();

        Assert.True(result.HasFlag(FileOptions.Asynchronous));
    }

    [Fact]
    public void GetFileOptions_IncludesSequentialScanFlag()
    {
        var result = _unalignedPolicy.GetFileOptions();

        Assert.True(result.HasFlag(FileOptions.SequentialScan));
    }

    [Fact]
    public void GetFileOptions_IncludesWriteThroughFlag()
    {
        var result = _unalignedPolicy.GetFileOptions();

        Assert.True(result.HasFlag(FileOptions.WriteThrough));
    }

    [Fact]
    public void GetFileOptions_IsConsistent()
    {
        var result1 = _unalignedPolicy.GetFileOptions();
        var result2 = _unalignedPolicy.GetFileOptions();

        Assert.Equal(result1, result2);
    }
}