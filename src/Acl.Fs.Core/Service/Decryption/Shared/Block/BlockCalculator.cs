using System.Runtime.CompilerServices;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;
using static Acl.Fs.Constant.Storage.StorageConstants;

namespace Acl.Fs.Core.Service.Decryption.Shared.Block;

internal static class BlockCalculator
{
    internal static long CalculateTotalBlocks(long encryptedStreamLength, int metadataBufferSize, int bufferSize)
    {
        var isSectorAligned = metadataBufferSize is SectorSize;
        var headerLen = isSectorAligned ? SectorSize : metadataBufferSize;

        var blockMetadataSize = isSectorAligned ? SectorSize : TagSize;
        var blockSize = blockMetadataSize + bufferSize;

        var dataLength = encryptedStreamLength - headerLen;

        if (dataLength <= 0)
            return 0;

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