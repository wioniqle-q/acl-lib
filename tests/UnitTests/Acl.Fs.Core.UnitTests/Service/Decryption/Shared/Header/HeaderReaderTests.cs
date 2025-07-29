using System.Buffers.Binary;
using Acl.Fs.Core.Abstractions;
using Acl.Fs.Core.Service.Decryption.Shared.Header;
using Moq;
using static Acl.Fs.Constant.Versioning.VersionConstants;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.UnitTests.Service.Decryption.Shared.Header;

public sealed class HeaderReaderTests
{
    private readonly HeaderReader _headerReader;
    private readonly Mock<IFileVersionValidator> _versionValidatorMock;

    public HeaderReaderTests()
    {
        _versionValidatorMock = new Mock<IFileVersionValidator>();
        _headerReader = new HeaderReader(_versionValidatorMock.Object);
    }

    [Fact]
    public async Task ReadHeaderAsync_ValidInput_ReturnsCorrectHeader()
    {
        const long originalSize = 1024L;

        var nonce = new byte[NonceSize];
        var chaCha20Salt = new byte[SaltSize];
        var argon2Salt = new byte[Argon2IdSaltSize];
        var metadataBuffer = new byte[HeaderSize];

        new Random(42).NextBytes(nonce);
        new Random(84).NextBytes(chaCha20Salt);
        new Random(126).NextBytes(argon2Salt);

        metadataBuffer[0] = CurrentMajorVersion;
        metadataBuffer[1] = CurrentMinorVersion;

        var offset = VersionHeaderSize;
        nonce.CopyTo(metadataBuffer, offset);
        offset += NonceSize;

        BinaryPrimitives.WriteInt64LittleEndian(metadataBuffer.AsSpan(offset), originalSize);
        offset += sizeof(long);

        chaCha20Salt.CopyTo(metadataBuffer, offset);
        offset += SaltSize;

        argon2Salt.CopyTo(metadataBuffer, offset);

        using var memoryStream = new MemoryStream(metadataBuffer);
        var resultChaCha20Salt = new byte[SaltSize];

        _versionValidatorMock.Setup(x => x.ValidateVersion(CurrentMajorVersion, CurrentMinorVersion));

        var header = await _headerReader.ReadHeaderAsync(memoryStream, metadataBuffer, resultChaCha20Salt,
            UnalignedHeaderSize, CancellationToken.None);

        Assert.Equal(CurrentMajorVersion, header.MajorVersion);
        Assert.Equal(CurrentMinorVersion, header.MinorVersion);
        Assert.Equal(originalSize, header.OriginalSize);
        Assert.Equal(nonce, header.Nonce);
        Assert.Equal(chaCha20Salt, header.ChaCha20Salt);
        Assert.Equal(argon2Salt, header.Argon2Salt);

        _versionValidatorMock.Verify(x => x.ValidateVersion(CurrentMajorVersion, CurrentMinorVersion), Times.Once);
    }

    [Fact]
    public async Task ReadHeaderAsync_CancelledToken_ThrowsOperationCanceledException()
    {
        using var memoryStream = new MemoryStream();
        var metadataBuffer = new byte[HeaderSize];
        var chaCha20Salt = new byte[SaltSize];

        var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await _headerReader.ReadHeaderAsync(memoryStream, metadataBuffer, chaCha20Salt, UnalignedHeaderSize,
                cts.Token));
    }

    [Fact]
    public async Task ReadHeaderAsync_InvalidVersion_CallsValidateVersion()
    {
        const byte invalidMajor = 255;
        const byte invalidMinor = 255;

        var metadataBuffer = new byte[HeaderSize];
        metadataBuffer[0] = invalidMajor;
        metadataBuffer[1] = invalidMinor;

        using var memoryStream = new MemoryStream(metadataBuffer);
        var chaCha20Salt = new byte[SaltSize];

        _versionValidatorMock.Setup(x => x.ValidateVersion(invalidMajor, invalidMinor))
            .Throws(new InvalidOperationException("Invalid version"));

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await _headerReader.ReadHeaderAsync(memoryStream, metadataBuffer, chaCha20Salt, UnalignedHeaderSize,
                CancellationToken.None));

        _versionValidatorMock.Verify(x => x.ValidateVersion(invalidMajor, invalidMinor), Times.Once);
    }

    [Fact]
    public void Constructor_NullVersionValidator_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new HeaderReader(null!));
    }

    [Fact]
    public async Task ReadHeaderAsync_StreamTooShort_ThrowsEndOfStreamException()
    {
        var shortBuffer = new byte[UnalignedHeaderSize - 1];
        using var memoryStream = new MemoryStream(shortBuffer);

        var metadataBuffer = new byte[HeaderSize];
        var chaCha20Salt = new byte[SaltSize];

        await Assert.ThrowsAsync<EndOfStreamException>(async () =>
            await _headerReader.ReadHeaderAsync(memoryStream, metadataBuffer, chaCha20Salt, UnalignedHeaderSize,
                CancellationToken.None));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    public async Task ReadHeaderAsync_DifferentNonceSizes_HandlesCorrectly(int nonceSize)
    {
        const long originalSize = 1024L;

        var nonce = new byte[nonceSize];
        var chaCha20Salt = new byte[SaltSize];
        var argon2Salt = new byte[Argon2IdSaltSize];
        var headerSize = VersionHeaderSize + nonceSize + sizeof(long) + SaltSize + Argon2IdSaltSize;
        var metadataBuffer = new byte[headerSize];

        new Random(42).NextBytes(nonce);
        new Random(84).NextBytes(chaCha20Salt);
        new Random(126).NextBytes(argon2Salt);

        metadataBuffer[0] = CurrentMajorVersion;
        metadataBuffer[1] = CurrentMinorVersion;

        var offset = VersionHeaderSize;
        nonce.CopyTo(metadataBuffer, offset);
        offset += nonceSize;

        BinaryPrimitives.WriteInt64LittleEndian(metadataBuffer.AsSpan(offset), originalSize);
        offset += sizeof(long);

        chaCha20Salt.CopyTo(metadataBuffer, offset);
        offset += SaltSize;

        argon2Salt.CopyTo(metadataBuffer, offset);

        using var memoryStream = new MemoryStream(metadataBuffer);
        var resultChaCha20Salt = new byte[SaltSize];

        _versionValidatorMock.Setup(x => x.ValidateVersion(CurrentMajorVersion, CurrentMinorVersion));

        var header = await _headerReader.ReadHeaderAsync(memoryStream, metadataBuffer, resultChaCha20Salt, headerSize,
            nonceSize, CancellationToken.None);

        Assert.Equal(nonce, header.Nonce);
        Assert.Equal(nonceSize, header.Nonce.Length);
    }

    [Fact]
    public async Task ReadHeaderAsync_DisposedStream_ThrowsObjectDisposedException()
    {
        var memoryStream = new MemoryStream();
        await memoryStream.DisposeAsync();

        var metadataBuffer = new byte[HeaderSize];
        var chaCha20Salt = new byte[SaltSize];

        await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
            await _headerReader.ReadHeaderAsync(memoryStream, metadataBuffer, chaCha20Salt, UnalignedHeaderSize,
                CancellationToken.None));
    }
}