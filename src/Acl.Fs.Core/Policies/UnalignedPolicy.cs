using System.Runtime.CompilerServices;
using Acl.Fs.Abstractions.Constants;
using Acl.Fs.Core.Interfaces;

namespace Acl.Fs.Core.Policies;

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
        return VersionConstants.UnalignedHeaderSize;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public FileOptions GetFileOptions()
    {
        return SectorFileOptions.GetFileOptions(false);
    }
}