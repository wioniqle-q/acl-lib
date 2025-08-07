using System.Buffers.Binary;
using System.Security.Cryptography;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Processor;
using Acl.Fs.Core.Resource;
using NSec.Cryptography;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.Service.Decryption.Shared.Provider;

internal sealed class XChaCha20Poly1305CryptoProvider : ICryptoProvider<Key>
{
    public void DecryptBlock(
        Key key,
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

        Span<byte> ciphertextWithTag = stackalloc byte[blockSize + TagSize];
        buffer.AsSpan(0, blockSize).CopyTo(ciphertextWithTag);
        tag.AsSpan(0, TagSize).CopyTo(ciphertextWithTag[blockSize..]);

        try
        {
            var algorithm = (NSec.Cryptography.XChaCha20Poly1305)key.Algorithm;

            var success = algorithm.Decrypt(
                key,
                chunkNonce.AsSpan(0, XChaCha20Poly1305NonceSize),
                associatedData,
                ciphertextWithTag,
                plaintext.AsSpan(0, blockSize));

            if (success is not true)
                throw new CryptographicException(ErrorMessages.DecryptionFailed);
        }
        finally
        {
            associatedData.Clear();
            ciphertextWithTag.Clear();
        }
    }
}