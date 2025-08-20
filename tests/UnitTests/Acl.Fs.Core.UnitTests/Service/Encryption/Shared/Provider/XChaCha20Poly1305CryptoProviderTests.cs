using Acl.Fs.Core.Service.Encryption.Shared.Provider;
using NSec.Cryptography;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.UnitTests.Service.Encryption.Shared.Provider;

public sealed class XChaCha20Poly1305CryptoProviderTests
{
    [Fact]
    public void EncryptBlock_CorrectlyEncryptsData()
    {
        const long blockIndex = 42L;

        var keyBytes = new byte[32];
        keyBytes.AsSpan().Fill(0x01);

        var algorithm = AeadAlgorithm.XChaCha20Poly1305;
        var key = Key.Import(algorithm, keyBytes, KeyBlobFormat.RawSymmetricKey);
        var provider = new XChaCha20Poly1305CryptoProvider();

        var buffer = new byte[16];
        buffer.AsSpan().Fill(0x04);

        var alignedSize = buffer.Length;
        var ciphertext = new byte[alignedSize];
        var tag = new byte[TagSize];

        var chunkNonce = new byte[XChaCha20Poly1305NonceSize];
        chunkNonce.AsSpan().Fill(0x02);

        var salt = new byte[SaltSize];
        salt.AsSpan().Fill(0x03);

        provider.EncryptBlock(key, buffer, ciphertext, tag, chunkNonce, alignedSize, blockIndex, salt);

        var associatedData = new byte[SaltSize + 8 + 4];
        var associatedDataSpan = associatedData.AsSpan();
        salt.AsSpan().CopyTo(associatedDataSpan[..SaltSize]);

        var blockIndexBytes = BitConverter.GetBytes(blockIndex);
        blockIndexBytes.AsSpan().CopyTo(associatedDataSpan.Slice(SaltSize, 8));

        var alignedSizeBytes = BitConverter.GetBytes(alignedSize);
        alignedSizeBytes.AsSpan().CopyTo(associatedDataSpan.Slice(SaltSize + 8, 4));

        var ciphertextWithTag = new byte[alignedSize + TagSize];
        ciphertext.AsSpan().CopyTo(ciphertextWithTag.AsSpan(0, alignedSize));
        tag.AsSpan().CopyTo(ciphertextWithTag.AsSpan(alignedSize, TagSize));

        var decrypted = new byte[alignedSize];
        var success = algorithm.Decrypt(key, chunkNonce.AsSpan(0, XChaCha20Poly1305NonceSize),
            associatedData, ciphertextWithTag, decrypted);

        Assert.True(success, "Decryption should succeed with correct parameters");
        Assert.Equal(buffer, decrypted);
    }

    [Fact]
    public void EncryptBlock_WithIncorrectBlockIndex_FailsDecryption()
    {
        const long blockIndex = 42L;
        const long wrongBlockIndex = 43L;

        var keyBytes = new byte[32];
        keyBytes.AsSpan().Fill(0x01);

        var algorithm = AeadAlgorithm.XChaCha20Poly1305;
        var key = Key.Import(algorithm, keyBytes, KeyBlobFormat.RawSymmetricKey);
        var provider = new XChaCha20Poly1305CryptoProvider();

        var buffer = new byte[16];
        buffer.AsSpan().Fill(0x04);

        var alignedSize = buffer.Length;
        var ciphertext = new byte[alignedSize];
        var tag = new byte[TagSize];

        var chunkNonce = new byte[XChaCha20Poly1305NonceSize];
        chunkNonce.AsSpan().Fill(0x02);

        var salt = new byte[SaltSize];
        salt.AsSpan().Fill(0x03);

        provider.EncryptBlock(key, buffer, ciphertext, tag, chunkNonce, alignedSize, blockIndex, salt);

        var associatedData = new byte[SaltSize + 8 + 4];
        var associatedDataSpan = associatedData.AsSpan();
        salt.AsSpan().CopyTo(associatedDataSpan[..SaltSize]);

        var blockIndexBytes = BitConverter.GetBytes(wrongBlockIndex);
        blockIndexBytes.AsSpan().CopyTo(associatedDataSpan.Slice(SaltSize, 8));

        var alignedSizeBytes = BitConverter.GetBytes(alignedSize);
        alignedSizeBytes.AsSpan().CopyTo(associatedDataSpan.Slice(SaltSize + 8, 4));

        var ciphertextWithTag = new byte[alignedSize + TagSize];
        ciphertext.AsSpan().CopyTo(ciphertextWithTag.AsSpan(0, alignedSize));
        tag.AsSpan().CopyTo(ciphertextWithTag.AsSpan(alignedSize, TagSize));

        var decrypted = new byte[alignedSize];
        var success = algorithm.Decrypt(key, chunkNonce.AsSpan(0, XChaCha20Poly1305NonceSize),
            associatedData, ciphertextWithTag, decrypted);

        Assert.False(success, "Decryption should fail with incorrect block index");
    }

    [Fact]
    public void EncryptBlock_WithIncorrectSalt_FailsDecryption()
    {
        const long blockIndex = 42L;

        var keyBytes = new byte[32];
        keyBytes.AsSpan().Fill(0x01);

        var algorithm = AeadAlgorithm.XChaCha20Poly1305;
        var key = Key.Import(algorithm, keyBytes, KeyBlobFormat.RawSymmetricKey);
        var provider = new XChaCha20Poly1305CryptoProvider();

        var buffer = new byte[16];
        buffer.AsSpan().Fill(0x04);

        var alignedSize = buffer.Length;
        var ciphertext = new byte[alignedSize];
        var tag = new byte[TagSize];

        var chunkNonce = new byte[XChaCha20Poly1305NonceSize];
        chunkNonce.AsSpan().Fill(0x02);

        var salt = new byte[SaltSize];
        salt.AsSpan().Fill(0x03);

        provider.EncryptBlock(key, buffer, ciphertext, tag, chunkNonce, alignedSize, blockIndex, salt);

        var wrongSalt = new byte[SaltSize];
        wrongSalt.AsSpan().Fill(0x05);

        var associatedData = new byte[SaltSize + 8 + 4];
        var associatedDataSpan = associatedData.AsSpan();
        wrongSalt.AsSpan().CopyTo(associatedDataSpan[..SaltSize]);

        var blockIndexBytes = BitConverter.GetBytes(blockIndex);
        blockIndexBytes.AsSpan().CopyTo(associatedDataSpan.Slice(SaltSize, 8));

        var alignedSizeBytes = BitConverter.GetBytes(alignedSize);
        alignedSizeBytes.AsSpan().CopyTo(associatedDataSpan.Slice(SaltSize + 8, 4));

        var ciphertextWithTag = new byte[alignedSize + TagSize];
        ciphertext.AsSpan().CopyTo(ciphertextWithTag.AsSpan(0, alignedSize));
        tag.AsSpan().CopyTo(ciphertextWithTag.AsSpan(alignedSize, TagSize));

        var decrypted = new byte[alignedSize];
        var success = algorithm.Decrypt(key, chunkNonce.AsSpan(0, XChaCha20Poly1305NonceSize),
            associatedData, ciphertextWithTag, decrypted);

        Assert.False(success, "Decryption should fail with incorrect salt");
    }

    [Fact]
    public void EncryptBlock_WithDifferentAlignedSizes_WorksCorrectly()
    {
        const long blockIndex = 1L;

        var keyBytes = new byte[32];
        keyBytes.AsSpan().Fill(0x01);

        var algorithm = AeadAlgorithm.XChaCha20Poly1305;
        var key = Key.Import(algorithm, keyBytes, KeyBlobFormat.RawSymmetricKey);
        var provider = new XChaCha20Poly1305CryptoProvider();

        var testSizes = new[] { 8, 16, 32, 64, 128, 256 };

        foreach (var size in testSizes)
        {
            var buffer = new byte[size];
            buffer.AsSpan().Fill((byte)(size % 256));

            var ciphertext = new byte[size];
            var tag = new byte[TagSize];

            var chunkNonce = new byte[XChaCha20Poly1305NonceSize];
            chunkNonce.AsSpan().Fill(0x02);

            var salt = new byte[SaltSize];
            salt.AsSpan().Fill(0x03);

            provider.EncryptBlock(key, buffer, ciphertext, tag, chunkNonce, size, blockIndex, salt);

            Assert.NotEqual(buffer, ciphertext);

            Assert.True(tag.Any(b => b is not 0), $"Tag should not be all zeros for size {size}");
        }
    }

    [Fact]
    public void EncryptBlock_WithSameInputs_ProducesDeterministicOutput()
    {
        const long blockIndex = 5L;

        var keyBytes = new byte[32];
        keyBytes.AsSpan().Fill(0x01);

        var algorithm = AeadAlgorithm.XChaCha20Poly1305;
        var key = Key.Import(algorithm, keyBytes, KeyBlobFormat.RawSymmetricKey);
        var provider = new XChaCha20Poly1305CryptoProvider();

        var buffer = new byte[32];
        buffer.AsSpan().Fill(0x04);

        var alignedSize = buffer.Length;

        var chunkNonce = new byte[XChaCha20Poly1305NonceSize];
        chunkNonce.AsSpan().Fill(0x02);

        var salt = new byte[SaltSize];
        salt.AsSpan().Fill(0x03);

        var ciphertext1 = new byte[alignedSize];
        var tag1 = new byte[TagSize];
        provider.EncryptBlock(key, buffer, ciphertext1, tag1, chunkNonce, alignedSize, blockIndex, salt);

        var ciphertext2 = new byte[alignedSize];
        var tag2 = new byte[TagSize];
        provider.EncryptBlock(key, buffer, ciphertext2, tag2, chunkNonce, alignedSize, blockIndex, salt);

        Assert.Equal(ciphertext1, ciphertext2);
        Assert.Equal(tag1, tag2);
    }

    [Fact]
    public void EncryptBlock_WithDifferentNonces_ProducesDifferentOutput()
    {
        const long blockIndex = 5L;

        var keyBytes = new byte[32];
        keyBytes.AsSpan().Fill(0x01);

        var algorithm = AeadAlgorithm.XChaCha20Poly1305;
        var key = Key.Import(algorithm, keyBytes, KeyBlobFormat.RawSymmetricKey);
        var provider = new XChaCha20Poly1305CryptoProvider();

        var buffer = new byte[32];
        buffer.AsSpan().Fill(0x04);

        var alignedSize = buffer.Length;

        var salt = new byte[SaltSize];
        salt.AsSpan().Fill(0x03);

        var chunkNonce1 = new byte[XChaCha20Poly1305NonceSize];
        chunkNonce1.AsSpan().Fill(0x02);

        var ciphertext1 = new byte[alignedSize];
        var tag1 = new byte[TagSize];
        provider.EncryptBlock(key, buffer, ciphertext1, tag1, chunkNonce1, alignedSize, blockIndex, salt);

        var chunkNonce2 = new byte[XChaCha20Poly1305NonceSize];
        chunkNonce2.AsSpan().Fill(0x07);

        var ciphertext2 = new byte[alignedSize];
        var tag2 = new byte[TagSize];
        provider.EncryptBlock(key, buffer, ciphertext2, tag2, chunkNonce2, alignedSize, blockIndex, salt);

        Assert.NotEqual(ciphertext1, ciphertext2);
        Assert.NotEqual(tag1, tag2);
    }
}