using System.Buffers.Binary;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Processor;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.Service.Encryption.Shared.Provider;

internal sealed class AesGcmCryptoProvider : ICryptoProvider<System.Security.Cryptography.AesGcm>
{
    public void EncryptBlock(
        System.Security.Cryptography.AesGcm aesGcm,
        byte[] buffer,
        byte[] ciphertext,
        byte[] tag,
        byte[] chunkNonce,
        int alignedSize,
        long blockIndex,
        byte[] salt)
    {
        Span<byte> associatedData = stackalloc byte[SaltSize + sizeof(long) + sizeof(int)];

        salt.AsSpan(0, Math.Min(SaltSize, salt.Length)).CopyTo(associatedData);

        BinaryPrimitives.WriteInt64LittleEndian(associatedData[SaltSize..], blockIndex);
        BinaryPrimitives.WriteInt32LittleEndian(associatedData[(SaltSize + sizeof(long))..], alignedSize);

        try
        {
            aesGcm.Encrypt(
                chunkNonce.AsSpan(0, NonceSize),
                buffer.AsSpan(0, alignedSize),
                ciphertext.AsSpan(0, alignedSize),
                tag.AsSpan(0, TagSize),
                associatedData);
        }
        finally
        {
            associatedData.Clear();
        }
    }
}