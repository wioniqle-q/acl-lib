using System.Buffers.Binary;
using System.Security.Cryptography;
using Acl.Fs.Core.Service.Decryption.Shared.Provider;
using NSec.Cryptography;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.UnitTests.Service.Decryption.Shared.Provider;

public sealed class XChaCha20Poly1305CryptoProviderTests
{
    [Fact]
    public void DecryptBlock_CorrectlyDecryptsData()
    {
        const long blockIndex = 0L;
        const int blockSize = 16;

        var keyBytes = new byte[32];
        for (var i = 0; i < 32; i++) keyBytes[i] = (byte)i;

        var algorithm = AeadAlgorithm.XChaCha20Poly1305;
        var key = Key.Import(algorithm, keyBytes, KeyBlobFormat.RawSymmetricKey);

        var nonce = new byte[XChaCha20Poly1305NonceSize];
        for (var i = 0; i < XChaCha20Poly1305NonceSize; i++) nonce[i] = (byte)i;

        var salt = new byte[SaltSize];
        for (var i = 0; i < SaltSize; i++) salt[i] = (byte)i;

        var plaintextOriginal = new byte[blockSize];
        for (var i = 0; i < blockSize; i++) plaintextOriginal[i] = 0xAA;

        var associatedData = new byte[SaltSize + 8 + 4];
        salt.AsSpan().CopyTo(associatedData.AsSpan(0, SaltSize));

        BinaryPrimitives.WriteInt64LittleEndian(associatedData.AsSpan(SaltSize), blockIndex);
        BinaryPrimitives.WriteInt32LittleEndian(associatedData.AsSpan(SaltSize + 8), blockSize);

        var ciphertextWithTag = new byte[blockSize + TagSize];
        algorithm.Encrypt(key, nonce, associatedData, plaintextOriginal, ciphertextWithTag);

        var ciphertext = new byte[blockSize];
        var tag = new byte[TagSize];
        ciphertextWithTag.AsSpan(0, blockSize).CopyTo(ciphertext);
        ciphertextWithTag.AsSpan(blockSize, TagSize).CopyTo(tag);

        var provider = new XChaCha20Poly1305CryptoProvider();
        var plaintextDecrypted = new byte[blockSize];

        provider.DecryptBlock(key, ciphertext, plaintextDecrypted, tag, nonce, salt, blockSize, blockIndex);

        Assert.Equal(plaintextOriginal, plaintextDecrypted);
    }

    [Fact]
    public void DecryptBlock_WithInvalidTag_ThrowsException()
    {
        const long blockIndex = 0L;
        const int blockSize = 16;

        var keyBytes = new byte[32];
        for (var i = 0; i < 32; i++) keyBytes[i] = (byte)i;

        var algorithm = AeadAlgorithm.XChaCha20Poly1305;
        var key = Key.Import(algorithm, keyBytes, KeyBlobFormat.RawSymmetricKey);

        var nonce = new byte[XChaCha20Poly1305NonceSize];
        for (var i = 0; i < XChaCha20Poly1305NonceSize; i++) nonce[i] = (byte)i;

        var salt = new byte[SaltSize];
        for (var i = 0; i < SaltSize; i++) salt[i] = (byte)i;

        var plaintextOriginal = new byte[blockSize];
        for (var i = 0; i < blockSize; i++) plaintextOriginal[i] = 0xAA;

        var associatedData = new byte[SaltSize + 8 + 4];
        salt.AsSpan().CopyTo(associatedData.AsSpan(0, SaltSize));
        BinaryPrimitives.WriteInt64LittleEndian(associatedData.AsSpan(SaltSize), blockIndex);
        BinaryPrimitives.WriteInt32LittleEndian(associatedData.AsSpan(SaltSize + 8), blockSize);

        var ciphertextWithTag = new byte[blockSize + TagSize];
        algorithm.Encrypt(key, nonce, associatedData, plaintextOriginal, ciphertextWithTag);

        var ciphertext = new byte[blockSize];
        var tag = new byte[TagSize];
        ciphertextWithTag.AsSpan(0, blockSize).CopyTo(ciphertext);
        ciphertextWithTag.AsSpan(blockSize, TagSize).CopyTo(tag);

        tag[0] ^= 1;

        var provider = new XChaCha20Poly1305CryptoProvider();
        var plaintextDecrypted = new byte[blockSize];

        Assert.ThrowsAny<CryptographicException>(() =>
            provider.DecryptBlock(key, ciphertext, plaintextDecrypted, tag, nonce, salt, blockSize, blockIndex));
    }

    [Fact]
    public void DecryptBlock_WithWrongBlockIndex_ThrowsException()
    {
        const long blockIndex = 0L;
        const long wrongBlockIndex = 1L;
        const int blockSize = 16;

        var keyBytes = new byte[32];
        for (var i = 0; i < 32; i++) keyBytes[i] = (byte)i;

        var algorithm = AeadAlgorithm.XChaCha20Poly1305;
        var key = Key.Import(algorithm, keyBytes, KeyBlobFormat.RawSymmetricKey);

        var nonce = new byte[XChaCha20Poly1305NonceSize];
        for (var i = 0; i < XChaCha20Poly1305NonceSize; i++) nonce[i] = (byte)i;

        var salt = new byte[SaltSize];
        for (var i = 0; i < SaltSize; i++) salt[i] = (byte)i;

        var plaintextOriginal = new byte[blockSize];
        for (var i = 0; i < blockSize; i++) plaintextOriginal[i] = 0xAA;

        var associatedData = new byte[SaltSize + 8 + 4];
        salt.AsSpan().CopyTo(associatedData.AsSpan(0, SaltSize));
        BinaryPrimitives.WriteInt64LittleEndian(associatedData.AsSpan(SaltSize), blockIndex);
        BinaryPrimitives.WriteInt32LittleEndian(associatedData.AsSpan(SaltSize + 8), blockSize);

        var ciphertextWithTag = new byte[blockSize + TagSize];
        algorithm.Encrypt(key, nonce, associatedData, plaintextOriginal, ciphertextWithTag);

        var ciphertext = new byte[blockSize];
        var tag = new byte[TagSize];
        ciphertextWithTag.AsSpan(0, blockSize).CopyTo(ciphertext);
        ciphertextWithTag.AsSpan(blockSize, TagSize).CopyTo(tag);

        var provider = new XChaCha20Poly1305CryptoProvider();
        var plaintextDecrypted = new byte[blockSize];

        Assert.ThrowsAny<CryptographicException>(() =>
            provider.DecryptBlock(key, ciphertext, plaintextDecrypted, tag, nonce, salt, blockSize, wrongBlockIndex));
    }

    [Fact]
    public void DecryptBlock_WithWrongSalt_ThrowsException()
    {
        const long blockIndex = 0L;
        const int blockSize = 16;

        var keyBytes = new byte[32];
        for (var i = 0; i < 32; i++) keyBytes[i] = (byte)i;

        var algorithm = AeadAlgorithm.XChaCha20Poly1305;
        var key = Key.Import(algorithm, keyBytes, KeyBlobFormat.RawSymmetricKey);

        var nonce = new byte[XChaCha20Poly1305NonceSize];
        for (var i = 0; i < XChaCha20Poly1305NonceSize; i++) nonce[i] = (byte)i;

        var salt = new byte[SaltSize];
        for (var i = 0; i < SaltSize; i++) salt[i] = (byte)i;

        var wrongSalt = new byte[SaltSize];
        for (var i = 0; i < SaltSize; i++) wrongSalt[i] = (byte)(i + 1);

        var plaintextOriginal = new byte[blockSize];
        for (var i = 0; i < blockSize; i++) plaintextOriginal[i] = 0xAA;

        var associatedData = new byte[SaltSize + 8 + 4];
        salt.AsSpan().CopyTo(associatedData.AsSpan(0, SaltSize));
        BinaryPrimitives.WriteInt64LittleEndian(associatedData.AsSpan(SaltSize), blockIndex);
        BinaryPrimitives.WriteInt32LittleEndian(associatedData.AsSpan(SaltSize + 8), blockSize);

        var ciphertextWithTag = new byte[blockSize + TagSize];
        algorithm.Encrypt(key, nonce, associatedData, plaintextOriginal, ciphertextWithTag);

        var ciphertext = new byte[blockSize];
        var tag = new byte[TagSize];
        ciphertextWithTag.AsSpan(0, blockSize).CopyTo(ciphertext);
        ciphertextWithTag.AsSpan(blockSize, TagSize).CopyTo(tag);

        var provider = new XChaCha20Poly1305CryptoProvider();
        var plaintextDecrypted = new byte[blockSize];

        Assert.ThrowsAny<CryptographicException>(() =>
            provider.DecryptBlock(key, ciphertext, plaintextDecrypted, tag, nonce, wrongSalt, blockSize, blockIndex));
    }

    [Fact]
    public void DecryptBlock_WithDifferentBlockSizes_WorksCorrectly()
    {
        const long blockIndex = 1L;

        var keyBytes = new byte[32];
        RandomNumberGenerator.Fill(keyBytes);

        var algorithm = AeadAlgorithm.XChaCha20Poly1305;
        var key = Key.Import(algorithm, keyBytes, KeyBlobFormat.RawSymmetricKey);

        var nonce = new byte[XChaCha20Poly1305NonceSize];
        RandomNumberGenerator.Fill(nonce);

        var salt = new byte[SaltSize];
        RandomNumberGenerator.Fill(salt);

        var testSizes = new[] { 8, 16, 32, 64, 128, 256 };

        foreach (var blockSize in testSizes)
        {
            var plaintextOriginal = new byte[blockSize];
            RandomNumberGenerator.Fill(plaintextOriginal);

            var associatedData = new byte[SaltSize + 8 + 4];
            salt.AsSpan().CopyTo(associatedData.AsSpan(0, SaltSize));
            BinaryPrimitives.WriteInt64LittleEndian(associatedData.AsSpan(SaltSize), blockIndex);
            BinaryPrimitives.WriteInt32LittleEndian(associatedData.AsSpan(SaltSize + 8), blockSize);

            var ciphertextWithTag = new byte[blockSize + TagSize];
            algorithm.Encrypt(key, nonce, associatedData, plaintextOriginal, ciphertextWithTag);

            var ciphertext = new byte[blockSize];
            var tag = new byte[TagSize];
            ciphertextWithTag.AsSpan(0, blockSize).CopyTo(ciphertext);
            ciphertextWithTag.AsSpan(blockSize, TagSize).CopyTo(tag);

            var provider = new XChaCha20Poly1305CryptoProvider();
            var plaintextDecrypted = new byte[blockSize];

            var exception = Record.Exception(() =>
                provider.DecryptBlock(key, ciphertext, plaintextDecrypted, tag, nonce, salt, blockSize, blockIndex));

            Assert.Null(exception);
            Assert.Equal(plaintextOriginal, plaintextDecrypted);
        }
    }

    [Fact]
    public void DecryptBlock_WithXChaCha20Poly1305EnhancedSecurity_Uses24ByteNonce()
    {
        const long blockIndex = 5L;
        const int blockSize = 32;

        var keyBytes = new byte[32];
        RandomNumberGenerator.Fill(keyBytes);

        var algorithm = AeadAlgorithm.XChaCha20Poly1305;
        var key = Key.Import(algorithm, keyBytes, KeyBlobFormat.RawSymmetricKey);

        var nonce = new byte[XChaCha20Poly1305NonceSize];
        RandomNumberGenerator.Fill(nonce);

        var salt = new byte[SaltSize];
        RandomNumberGenerator.Fill(salt);

        var plaintextOriginal = new byte[blockSize];
        RandomNumberGenerator.Fill(plaintextOriginal);

        var associatedData = new byte[SaltSize + 8 + 4];
        salt.AsSpan().CopyTo(associatedData.AsSpan(0, SaltSize));
        BinaryPrimitives.WriteInt64LittleEndian(associatedData.AsSpan(SaltSize), blockIndex);
        BinaryPrimitives.WriteInt32LittleEndian(associatedData.AsSpan(SaltSize + 8), blockSize);

        var ciphertextWithTag = new byte[blockSize + TagSize];
        algorithm.Encrypt(key, nonce, associatedData, plaintextOriginal, ciphertextWithTag);

        var ciphertext = new byte[blockSize];
        var tag = new byte[TagSize];
        ciphertextWithTag.AsSpan(0, blockSize).CopyTo(ciphertext);
        ciphertextWithTag.AsSpan(blockSize, TagSize).CopyTo(tag);

        var provider = new XChaCha20Poly1305CryptoProvider();
        var plaintextDecrypted = new byte[blockSize];

        var exception = Record.Exception(() =>
            provider.DecryptBlock(key, ciphertext, plaintextDecrypted, tag, nonce, salt, blockSize, blockIndex));

        Assert.Null(exception);
        Assert.Equal(plaintextOriginal, plaintextDecrypted);

        Assert.Equal(24, XChaCha20Poly1305NonceSize);
        Assert.Equal(24, nonce.Length);
    }

    [Fact]
    public void DecryptBlock_WithConsistentInputs_ProducesCorrectOutput()
    {
        const long blockIndex = 10L;
        const int blockSize = 64;

        var keyBytes = new byte[32];
        for (var i = 0; i < 32; i++) keyBytes[i] = (byte)(i * 3 % 256);

        var algorithm = AeadAlgorithm.XChaCha20Poly1305;
        var key = Key.Import(algorithm, keyBytes, KeyBlobFormat.RawSymmetricKey);

        var nonce = new byte[XChaCha20Poly1305NonceSize];
        for (var i = 0; i < XChaCha20Poly1305NonceSize; i++) nonce[i] = (byte)(i * 5 % 256);

        var salt = new byte[SaltSize];
        for (var i = 0; i < SaltSize; i++) salt[i] = (byte)(i * 7 % 256);

        var plaintextOriginal = new byte[blockSize];
        for (var i = 0; i < blockSize; i++) plaintextOriginal[i] = (byte)(i * 11 % 256);

        var associatedData = new byte[SaltSize + 8 + 4];
        salt.AsSpan().CopyTo(associatedData.AsSpan(0, SaltSize));
        BinaryPrimitives.WriteInt64LittleEndian(associatedData.AsSpan(SaltSize), blockIndex);
        BinaryPrimitives.WriteInt32LittleEndian(associatedData.AsSpan(SaltSize + 8), blockSize);

        var ciphertextWithTag = new byte[blockSize + TagSize];
        algorithm.Encrypt(key, nonce, associatedData, plaintextOriginal, ciphertextWithTag);

        var ciphertext = new byte[blockSize];
        var tag = new byte[TagSize];
        ciphertextWithTag.AsSpan(0, blockSize).CopyTo(ciphertext);
        ciphertextWithTag.AsSpan(blockSize, TagSize).CopyTo(tag);

        var provider = new XChaCha20Poly1305CryptoProvider();

        for (var i = 0; i < 3; i++)
        {
            var plaintextDecrypted = new byte[blockSize];
            provider.DecryptBlock(key, ciphertext, plaintextDecrypted, tag, nonce, salt, blockSize, blockIndex);

            Assert.Equal(plaintextOriginal, plaintextDecrypted);
        }
    }
}