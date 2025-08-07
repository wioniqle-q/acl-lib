namespace Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Processor;

internal interface ICryptoProvider<in T>
{
    void EncryptBlock(
        T cryptoAlgorithm,
        byte[] buffer,
        byte[] ciphertext,
        byte[] tag,
        byte[] chunkNonce,
        int alignedSize,
        long blockIndex,
        byte[] salt);
}