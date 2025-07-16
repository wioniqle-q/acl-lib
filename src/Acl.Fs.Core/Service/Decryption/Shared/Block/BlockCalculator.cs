using System.Runtime.CompilerServices;
using Acl.Fs.Constant.Versioning;
using static Acl.Fs.Constant.Cryptography.KeyVaultConstants;
using static Acl.Fs.Constant.Storage.StorageConstants;

namespace Acl.Fs.Core.Service.Decryption.Shared.Block;

internal static class BlockCalculator
{
    internal static long CalculateTotalBlocks(long encryptedStreamLength, int metadataBufferSize, int bufferSize)
    {
        var isSectorAligned = metadataBufferSize is SectorSize;
        var headerLen = isSectorAligned ? SectorSize : VersionConstants.UnalignedHeaderSize;

        var blockMetadataSize = isSectorAligned ? SectorSize : TagSize;
        var blockSize = blockMetadataSize + bufferSize;

        var dataLength = encryptedStreamLength - headerLen;
        return (dataLength + blockSize - 1) / blockSize;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static int CalculateBytesToWrite(int bytesRead, long originalSize, long processedBytes)
    {
        return (int)Math.Min(bytesRead, originalSize - processedBytes);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static bool IsLastBlock(long processedBytes, int bytesRead, long originalSize)
    {
        return processedBytes + bytesRead >= originalSize;
    }
}