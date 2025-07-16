using System.Runtime.CompilerServices;
using Acl.Fs.Constant.Versioning;
using Acl.Fs.Core.Abstractions;
using Acl.Fs.Core.Utility;

namespace Acl.Fs.Core.Policy;

internal sealed class AlignedPolicy : IAlignmentPolicy
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int CalculateProcessingSize(int bytesRead, bool isLastBlock)
    {
        return CryptoPrimitives.CalculateAlignedSize(bytesRead, isLastBlock);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int GetMetadataBufferSize()
    {
        return VersionConstants.HeaderSize;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public FileOptions GetFileOptions()
    {
        return SectorFileOptions.GetFileOptions(true);
    }
}