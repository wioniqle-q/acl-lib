using System.Runtime.CompilerServices;
using Acl.Fs.Core.Interfaces;
using Acl.Fs.Core.Utilities;
using static Acl.Fs.Abstractions.Constants.StorageConstants;

namespace Acl.Fs.Core.Services.Policies;

internal sealed class AlignedPolicy : IAlignmentPolicy
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int CalculateProcessingSize(int bytesRead, bool isLastBlock)
    {
        return CryptoUtilities.CalculateAlignedSize(bytesRead, isLastBlock);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int GetMetadataBufferSize()
    {
        return SectorSize;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public FileOptions GetFileOptions()
    {
        return SectorFileOptions.GetFileOptions(true);
    }
}