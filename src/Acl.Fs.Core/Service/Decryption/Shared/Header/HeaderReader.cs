using System.Buffers.Binary;
using Acl.Fs.Constant.Versioning;
using Acl.Fs.Core.Abstractions;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Header;
using Acl.Fs.Core.Utility;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.Service.Decryption.Shared.Header;

internal sealed class HeaderReader(IFileVersionValidator versionValidator) : IHeaderReader
{
    private readonly IFileVersionValidator _versionValidator =
        versionValidator ?? throw new ArgumentNullException(nameof(versionValidator));

    public async Task<Abstractions.Service.Decryption.Shared.Header.Header> ReadHeaderAsync(
        System.IO.Stream sourceStream,
        byte[] metadataBuffer,
        byte[] chaCha20Salt,
        int metadataBufferSize,
        CancellationToken cancellationToken)
    {
        return await ReadHeaderAsync(sourceStream, metadataBuffer, chaCha20Salt, metadataBufferSize, NonceSize,
            cancellationToken);
    }

    public async Task<Abstractions.Service.Decryption.Shared.Header.Header> ReadHeaderAsync(
        System.IO.Stream sourceStream,
        byte[] metadataBuffer,
        byte[] chaCha20Salt,
        int metadataBufferSize,
        int nonceSize,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        await sourceStream.ReadExactlyAsync(
            metadataBuffer.AsMemory(0, metadataBufferSize),
            cancellationToken);

        var metadataSpan = metadataBuffer.AsSpan();

        var majorVersion = metadataSpan[0];
        var minorVersion = metadataSpan[1];

        _versionValidator.ValidateVersion(majorVersion, minorVersion);

        var offset = VersionConstants.VersionHeaderSize;

        var nonce = metadataSpan.Slice(offset, nonceSize);
        offset += nonceSize;

        var originalSize = BinaryPrimitives.ReadInt64LittleEndian(metadataSpan[offset..]);
        offset += sizeof(long);

        var headerSalt = metadataSpan.Slice(offset, SaltSize);
        headerSalt.CopyTo(chaCha20Salt);
        offset += SaltSize;

        CryptoOperations.ValidateHeaderSalt(nonce, headerSalt);

        var argon2Salt = new byte[Argon2IdSaltSize];
        metadataSpan.Slice(offset, Argon2IdSaltSize).CopyTo(argon2Salt);

        return new Abstractions.Service.Decryption.Shared.Header.Header(majorVersion, minorVersion, originalSize,
            nonce.ToArray(), chaCha20Salt, argon2Salt);
    }
}