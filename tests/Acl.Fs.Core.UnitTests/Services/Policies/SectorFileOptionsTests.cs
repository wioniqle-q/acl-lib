using Acl.Fs.Core.Policies;

namespace Acl.Fs.Core.UnitTests.Services.Policies;

public sealed class SectorFileOptionsTests
{
    [Fact]
    public void GetFileOptions_SectorAlignedTrue_IncludesSectorAlignedFlag()
    {
        var result = SectorFileOptions.GetFileOptions(true);

        const FileOptions expectedOptions = FileOptions.Asynchronous |
                                            FileOptions.SequentialScan |
                                            FileOptions.WriteThrough |
                                            (FileOptions)0x20000000;

        Assert.Equal(expectedOptions, result);
    }

    [Fact]
    public void GetFileOptions_SectorAlignedTrue_HasAllExpectedFlags()
    {
        var result = SectorFileOptions.GetFileOptions(true);

        Assert.True(result.HasFlag(FileOptions.Asynchronous));
        Assert.True(result.HasFlag(FileOptions.SequentialScan));
        Assert.True(result.HasFlag(FileOptions.WriteThrough));
        Assert.True(result.HasFlag((FileOptions)0x20000000));
    }

    [Fact]
    public void GetFileOptions_SectorAlignedFalse_DoesNotIncludeSectorAlignedFlag()
    {
        var result = SectorFileOptions.GetFileOptions(false);

        const FileOptions expectedOptions = FileOptions.Asynchronous |
                                            FileOptions.SequentialScan |
                                            FileOptions.WriteThrough;

        Assert.Equal(expectedOptions, result);
    }

    [Fact]
    public void GetFileOptions_SectorAlignedFalse_HasBasicFlags()
    {
        var result = SectorFileOptions.GetFileOptions(false);

        Assert.True(result.HasFlag(FileOptions.Asynchronous));
        Assert.True(result.HasFlag(FileOptions.SequentialScan));
        Assert.True(result.HasFlag(FileOptions.WriteThrough));
        Assert.False(result.HasFlag((FileOptions)0x20000000));
    }

    [Fact]
    public void GetFileOptions_AlignedVsUnaligned_DifferOnlyBySectorFlag()
    {
        var aligned = SectorFileOptions.GetFileOptions(true);
        var unaligned = SectorFileOptions.GetFileOptions(false);

        var difference = aligned ^ unaligned;

        Assert.Equal((FileOptions)0x20000000, difference);
    }

    [Fact]
    public void GetFileOptions_IsConsistent()
    {
        var result1 = SectorFileOptions.GetFileOptions(true);
        var result2 = SectorFileOptions.GetFileOptions(true);
        var result3 = SectorFileOptions.GetFileOptions(false);
        var result4 = SectorFileOptions.GetFileOptions(false);

        Assert.Equal(result1, result2);
        Assert.Equal(result3, result4);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void GetFileOptions_AlwaysIncludesBaseFlags(bool sectorAligned)
    {
        var result = SectorFileOptions.GetFileOptions(sectorAligned);

        Assert.True(result.HasFlag(FileOptions.Asynchronous));
        Assert.True(result.HasFlag(FileOptions.SequentialScan));
        Assert.True(result.HasFlag(FileOptions.WriteThrough));
    }

    [Fact]
    public void GetFileOptions_SectorAlignedFlag_OnlySetWhenTrue()
    {
        var alignedResult = SectorFileOptions.GetFileOptions(true);
        var unalignedResult = SectorFileOptions.GetFileOptions(false);

        Assert.True(alignedResult.HasFlag((FileOptions)0x20000000));
        Assert.False(unalignedResult.HasFlag((FileOptions)0x20000000));
    }
}