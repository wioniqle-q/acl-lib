using System.Security.Cryptography;
using Acl.Fs.Core.Service.Encryption.Shared.Provider;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.UnitTests.Service.Encryption.Shared.Provider;

public sealed class ChaChaPoly201305CryptoProviderTests
{
    [Fact]
    public void EncryptBlock_CorrectlyEncryptsData()
    {
        const long blockIndex = 42L;

        var key = new byte[32];
        key.AsSpan().Fill(0x01);

        var chacha = new System.Security.Cryptography.ChaCha20Poly1305(key);
        var provider = new ChaCha20Poly1305CryptoProvider();

        var buffer = new byte[16];
        buffer.AsSpan().Fill(0x04);

        var alignedSize = buffer.Length;
        var ciphertext = new byte[alignedSize];
        var tag = new byte[TagSize];

        var chunkNonce = new byte[NonceSize];
        chunkNonce.AsSpan().Fill(0x02);

        var salt = new byte[SaltSize];
        salt.AsSpan().Fill(0x03);

        provider.EncryptBlock(chacha, buffer, ciphertext, tag, chunkNonce, alignedSize, blockIndex, salt);

        var associatedData = new byte[SaltSize + 8 + 4];

        var associatedDataSpan = associatedData.AsSpan();
        salt.AsSpan().CopyTo(associatedDataSpan[..SaltSize]);

        var blockIndexBytes = BitConverter.GetBytes(blockIndex);
        blockIndexBytes.AsSpan().CopyTo(associatedDataSpan.Slice(SaltSize, 8));

        var alignedSizeBytes = BitConverter.GetBytes(alignedSize);
        alignedSizeBytes.AsSpan().CopyTo(associatedDataSpan.Slice(SaltSize + 8, 4));

        var decrypted = new byte[alignedSize];
        chacha.Decrypt(chunkNonce, ciphertext, tag, decrypted, associatedData);

        Assert.Equal(buffer, decrypted);
    }

    [Fact]
    public void EncryptBlock_WithIncorrectBlockIndex_FailsDecryption()
    {
        const long blockIndex = 42L;
        const long wrongBlockIndex = 43L;

        var key = new byte[32];
        key.AsSpan().Fill(0x01);

        var chacha = new System.Security.Cryptography.ChaCha20Poly1305(key);
        var provider = new ChaCha20Poly1305CryptoProvider();

        var buffer = new byte[16];
        buffer.AsSpan().Fill(0x04);

        var alignedSize = buffer.Length;
        var ciphertext = new byte[alignedSize];
        var tag = new byte[TagSize];

        var chunkNonce = new byte[NonceSize];
        chunkNonce.AsSpan().Fill(0x02);

        var salt = new byte[SaltSize];
        salt.AsSpan().Fill(0x03);

        provider.EncryptBlock(chacha, buffer, ciphertext, tag, chunkNonce, alignedSize, blockIndex, salt);

        var associatedData = new byte[SaltSize + 8 + 4];

        var associatedDataSpan = associatedData.AsSpan();
        salt.AsSpan().CopyTo(associatedDataSpan[..SaltSize]);

        var blockIndexBytes = BitConverter.GetBytes(wrongBlockIndex);
        blockIndexBytes.AsSpan().CopyTo(associatedDataSpan.Slice(SaltSize, 8));

        var alignedSizeBytes = BitConverter.GetBytes(alignedSize);
        alignedSizeBytes.AsSpan().CopyTo(associatedDataSpan.Slice(SaltSize + 8, 4));

        var decrypted = new byte[alignedSize];
        Assert.Throws<AuthenticationTagMismatchException>(() =>
            chacha.Decrypt(chunkNonce, ciphertext, tag, decrypted, associatedData));
    }
}