using System.Runtime.CompilerServices;
using Acl.Fs.Constant.Versioning;
using Acl.Fs.Core.Abstractions;

namespace Acl.Fs.Core.Policy;

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