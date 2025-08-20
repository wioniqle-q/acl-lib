namespace Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Processor;

internal interface ICryptoProvider<in T>
{
    void DecryptBlock(
        T cryptoAlgorithm,
        byte[] buffer,
        byte[] plaintext,
        byte[] tag,
        byte[] chunkNonce,
        byte[] salt,
        int blockSize,
        long blockIndex);
}