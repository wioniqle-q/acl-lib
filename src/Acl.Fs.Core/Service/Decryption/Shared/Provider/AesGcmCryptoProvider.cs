using System.Buffers.Binary;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Processor;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.Service.Decryption.Shared.Provider;

internal sealed class AesGcmCryptoProvider : ICryptoProvider<System.Security.Cryptography.AesGcm>
{
    public void DecryptBlock(
        System.Security.Cryptography.AesGcm aesGcm,
        byte[] buffer,
        byte[] plaintext,
        byte[] tag,
        byte[] chunkNonce,
        byte[] salt,
        int blockSize,
        long blockIndex)
    {
        Span<byte> associatedData = stackalloc byte[SaltSize + sizeof(long) + sizeof(int)];

        salt.AsSpan(0, Math.Min(SaltSize, salt.Length)).CopyTo(associatedData);

        BinaryPrimitives.WriteInt64LittleEndian(associatedData[SaltSize..], blockIndex);
        BinaryPrimitives.WriteInt32LittleEndian(associatedData[(SaltSize + sizeof(long))..], blockSize);

        try
        {
            aesGcm.Decrypt(
                chunkNonce.AsSpan(0, NonceSize),
                buffer.AsSpan(0, blockSize),
                tag.AsSpan(0, TagSize),
                plaintext.AsSpan(0, blockSize),
                associatedData);
        }
        finally
        {
            associatedData.Clear();
        }
    }
}