using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Validation;
using Acl.Fs.Core.Resource;

namespace Acl.Fs.Core.Service.Decryption.Shared.Validation;

internal sealed class BlockValidator : IBlockValidator
{
    public long ValidateAndCalculateBytes(long processedBytes, long originalSize, int bytesRead, string prefix)
    {
        var available = originalSize - processedBytes;
        if (available < 0)
            throw new InvalidOperationException(string.Format(
                prefix + AuditMessages.ProcessedBytesExceeded,
                processedBytes, originalSize));

        var bytesToWrite = (int)Math.Min(bytesRead, available);
        if (bytesToWrite < 0)
            throw new InvalidOperationException(string.Format(
                prefix + AuditMessages.NegativeBytesToWrite, bytesToWrite));

        processedBytes += bytesToWrite;

        if (processedBytes > originalSize)
            throw new InvalidOperationException(string.Format(
                prefix + AuditMessages.WrittenMoreBytesThanIntended,
                processedBytes, originalSize));

        return processedBytes;
    }

    public void ValidateBlockWriteParameters(int bytesRead, long originalSize, long processedBytes,
        int blockSize, int plaintextLength)
    {
        var bytesToWrite = (int)Math.Min(bytesRead, originalSize - processedBytes);
        if (bytesToWrite < 0)
            throw new InvalidOperationException(string.Format(AuditMessages.NegativeBytesToWrite, bytesToWrite));

        if (blockSize > plaintextLength)
            throw new InvalidOperationException(string.Format(AuditMessages.BlockSizeExceedsPlaintextBuffer, blockSize,
                plaintextLength));

        if (processedBytes + bytesToWrite > originalSize)
            throw new InvalidOperationException(string.Format(AuditMessages.WrittenMoreBytesThanIntended,
                processedBytes + bytesToWrite, originalSize));
    }
}