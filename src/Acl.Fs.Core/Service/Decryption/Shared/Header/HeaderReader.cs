using System.Buffers.Binary;
using Acl.Fs.Constant.Versioning;
using Acl.Fs.Core.Abstractions;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Header;
using static Acl.Fs.Constant.Cryptography.KeyVaultConstants;

namespace Acl.Fs.Core.Service.Decryption.Shared.Header;

internal sealed class HeaderReader(IFileVersionValidator versionValidator) : IHeaderReader
{
    private readonly IFileVersionValidator _versionValidator =
        versionValidator ?? throw new ArgumentNullException(nameof(versionValidator));

    public async Task<Abstractions.Service.Decryption.Shared.Header.Header> ReadHeaderAsync(
        System.IO.Stream sourceStream,
        byte[] metadataBuffer,
        byte[] salt,
        int metadataBufferSize,
        CancellationToken cancellationToken)
    {
        await sourceStream.ReadExactlyAsync(
            metadataBuffer.AsMemory(0, metadataBufferSize),
            cancellationToken);

        var metadataSpan = metadataBuffer.AsSpan();

        var majorVersion = metadataSpan[0];
        var minorVersion = metadataSpan[1];

        _versionValidator.ValidateVersion(majorVersion, minorVersion);

        var nonce = metadataSpan.Slice(VersionConstants.VersionHeaderSize, NonceSize);
        var originalSize = BinaryPrimitives.ReadInt64LittleEndian(
            metadataSpan[(VersionConstants.VersionHeaderSize + NonceSize)..]);

        nonce.CopyTo(metadataBuffer.AsSpan(0, NonceSize));

        metadataSpan.Slice(VersionConstants.VersionHeaderSize + NonceSize + sizeof(long), SaltSize)
            .CopyTo(salt);

        return new Abstractions.Service.Decryption.Shared.Header.Header(majorVersion, minorVersion, originalSize,
            nonce.ToArray(), salt);
    }
}