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
    public async Task ReadHeaderAsync_SuccessfulReading_ReturnsCorrectHeader()
    {
        const long originalSize = 123456789L;

        var nonce = new byte[NonceSize];
        var salt = new byte[SaltSize];

        var headerData = CreateHeaderData(CurrentMajorVersion, CurrentMinorVersion, nonce, originalSize, salt);

        using var stream = new MemoryStream(headerData);

        var metadataBuffer = new byte[HeaderSize];
        var saltBuffer = new byte[SaltSize];
        var metadataBufferSize = HeaderSize;

        var header = await _headerReader.ReadHeaderAsync(stream, metadataBuffer, saltBuffer, metadataBufferSize,
            CancellationToken.None);

        Assert.Equal(CurrentMajorVersion, header.MajorVersion);
        Assert.Equal(CurrentMinorVersion, header.MinorVersion);
        Assert.Equal(originalSize, header.OriginalSize);
        Assert.Equal(nonce, header.Nonce);
        Assert.Equal(salt, header.ChaCha20Salt);

        _versionValidatorMock.Verify(v => v.ValidateVersion(CurrentMajorVersion, CurrentMinorVersion), Times.Once());
    }

    [Fact]
    public async Task ReadHeaderAsync_InsufficientData_ThrowsEndOfStreamException()
    {
        var insufficientData = new byte[HeaderSize - 1];

        using var stream = new MemoryStream(insufficientData);

        var metadataBuffer = new byte[HeaderSize];
        var saltBuffer = new byte[SaltSize];
        var metadataBufferSize = HeaderSize;

        await Assert.ThrowsAsync<EndOfStreamException>(() =>
            _headerReader.ReadHeaderAsync(stream, metadataBuffer, saltBuffer, metadataBufferSize,
                CancellationToken.None));
    }

    [Fact]
    public async Task ReadHeaderAsync_CanceledToken_ThrowsOperationCanceledException()
    {
        var data = new byte[HeaderSize];

        using var stream = new MemoryStream(data);

        var metadataBuffer = new byte[HeaderSize];
        var saltBuffer = new byte[SaltSize];
        var metadataBufferSize = HeaderSize;

        var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            _headerReader.ReadHeaderAsync(stream, metadataBuffer, saltBuffer, metadataBufferSize, cts.Token));
    }

    private static byte[] CreateHeaderData(byte majorVersion, byte minorVersion, byte[] nonce, long originalSize,
        byte[] salt)
    {
        var headerData = new byte[HeaderSize];

        headerData[0] = majorVersion;
        headerData[1] = minorVersion;

        nonce.AsSpan().CopyTo(headerData.AsSpan(VersionHeaderSize, NonceSize));

        var sizeBytes = BitConverter.GetBytes(originalSize);
        sizeBytes.AsSpan().CopyTo(headerData.AsSpan(VersionHeaderSize + NonceSize, sizeof(long)));

        salt.AsSpan().CopyTo(headerData.AsSpan(VersionHeaderSize + NonceSize + sizeof(long), SaltSize));

        return headerData;
    }
}