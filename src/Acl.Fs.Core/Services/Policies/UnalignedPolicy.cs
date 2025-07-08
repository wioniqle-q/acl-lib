using Acl.Fs.Abstractions.Constants;
using Acl.Fs.Core.Interfaces;
using static Acl.Fs.Abstractions.Constants.KeyVaultConstants;

namespace Acl.Fs.Core.Services.Policies;

internal sealed class UnalignedPolicy : IAlignmentPolicy
{
    public int CalculateProcessingSize(int bytesRead, bool isLastBlock)
    {
        return bytesRead;
    }

    public int GetMetadataBufferSize()
    {
        return VersionConstants.VersionHeaderSize + NonceSize + sizeof(long) + SaltSize;
    }

    public FileOptions GetFileOptions()
    {
        return SectorFileOptions.GetFileOptions(false);
    }
}