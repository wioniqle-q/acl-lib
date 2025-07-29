using System.Buffers.Binary;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Processor;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.Service.Decryption.Shared.Provider;

internal sealed class ChaCha20Poly1305CryptoProvider : ICryptoProvider<System.Security.Cryptography.ChaCha20Poly1305>
{
    public void DecryptBlock(
        System.Security.Cryptography.ChaCha20Poly1305 chaCha20Poly1305,
        byte[] buffer,
        byte[] plaintext,
        byte[] tag,
        byte[] chunkNonce,
        byte[] salt,
        int blockSize,
        long blockIndex)
    {
        Span<byte> associatedData = stackalloc byte[64 + sizeof(long) + sizeof(int)];

        salt.AsSpan(0, Math.Min(64, salt.Length)).CopyTo(associatedData);

        BinaryPrimitives.WriteInt64LittleEndian(associatedData[64..], blockIndex);
        BinaryPrimitives.WriteInt32LittleEndian(associatedData[72..], blockSize);

        chaCha20Poly1305.Decrypt(
            chunkNonce.AsSpan(0, NonceSize),
            buffer.AsSpan(0, blockSize),
            tag.AsSpan(0, TagSize),
            plaintext.AsSpan(0, blockSize),
            associatedData);
    }
}