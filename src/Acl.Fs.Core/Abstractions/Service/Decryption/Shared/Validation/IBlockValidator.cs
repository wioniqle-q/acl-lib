namespace Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Validation;

internal interface IBlockValidator
{
    long ValidateAndCalculateBytes(long processedBytes, long originalSize, int bytesRead, string prefix);

    void ValidateBlockWriteParameters(int bytesRead, long originalSize, long processedBytes,
        int blockSize, int plaintextLength);
}