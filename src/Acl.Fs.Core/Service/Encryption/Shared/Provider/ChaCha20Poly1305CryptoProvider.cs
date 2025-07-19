using System.Buffers.Binary;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Processor;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.Service.Encryption.Shared.Provider;

internal sealed class ChaCha20Poly1305CryptoProvider : ICryptoProvider<System.Security.Cryptography.ChaCha20Poly1305>
{
    public void EncryptBlock(
        System.Security.Cryptography.ChaCha20Poly1305 chaCha20Poly1305,
        byte[] buffer,
        byte[] ciphertext,
        byte[] tag,
        byte[] chunkNonce,
        int alignedSize,
        long blockIndex,
        byte[] salt)
    {
        Span<byte> associatedData = stackalloc byte[64 + sizeof(long) + sizeof(int)];

        salt.AsSpan(0, Math.Min(64, salt.Length)).CopyTo(associatedData);

        BinaryPrimitives.WriteInt64LittleEndian(associatedData[64..], blockIndex);
        BinaryPrimitives.WriteInt32LittleEndian(associatedData[72..], alignedSize);

        chaCha20Poly1305.Encrypt(
            chunkNonce.AsSpan(0, NonceSize),
            buffer.AsSpan(0, alignedSize),
            ciphertext.AsSpan(0, alignedSize),
            tag.AsSpan(0, TagSize),
            associatedData);
    }
}