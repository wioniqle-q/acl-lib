using System.Runtime.CompilerServices;
using Acl.Fs.Abstractions.Constants;
using Acl.Fs.Core.Interfaces;
using static Acl.Fs.Abstractions.Constants.KeyVaultConstants;

namespace Acl.Fs.Core.Services.Policies;

internal sealed class UnalignedPolicy : IAlignmentPolicy
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int CalculateProcessingSize(int bytesRead, bool isLastBlock)
    {
        return bytesRead;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int GetMetadataBufferSize()
    {
        return VersionConstants.VersionHeaderSize + NonceSize + sizeof(long) + SaltSize;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public FileOptions GetFileOptions()
    {
        return SectorFileOptions.GetFileOptions(false);
    }
}