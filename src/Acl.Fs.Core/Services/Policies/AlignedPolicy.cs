using Acl.Fs.Core.Interfaces;
using Acl.Fs.Core.Utilities;
using static Acl.Fs.Abstractions.Constants.StorageConstants;

namespace Acl.Fs.Core.Services.Policies;

internal sealed class AlignedPolicy : IAlignmentPolicy
{
    public int CalculateProcessingSize(int bytesRead, bool isLastBlock)
    {
        return CryptoUtilities.CalculateAlignedSize(bytesRead, isLastBlock);
    }

    public int GetMetadataBufferSize()
    {
        return SectorSize;
    }

    public FileOptions GetFileOptions()
    {
        return SectorFileOptions.GetFileOptions(true);
    }
}