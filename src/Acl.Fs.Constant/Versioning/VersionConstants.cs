using Acl.Fs.Constant.Cryptography;
using Acl.Fs.Constant.Storage;

namespace Acl.Fs.Constant.Versioning;

internal static class VersionConstants
{
    internal const byte CurrentMajorVersion = 0;
    internal const byte CurrentMinorVersion = 1;

    internal const int VersionHeaderSize = 2;

    internal static int UnalignedHeaderSize =>
        VersionHeaderSize + CryptoConstants.NonceSize + sizeof(long) + CryptoConstants.SaltSize +
        CryptoConstants.Argon2IdSaltSize;

    internal static int XChaCha20Poly1305UnalignedHeaderSize =>
        VersionHeaderSize + CryptoConstants.XChaCha20Poly1305NonceSize + sizeof(long) + CryptoConstants.SaltSize +
        CryptoConstants.Argon2IdSaltSize;

    internal static int HeaderSize => (UnalignedHeaderSize + StorageConstants.SectorSize - 1) /
        StorageConstants.SectorSize * StorageConstants.SectorSize;

    internal static int XChaCha20Poly1305HeaderSize =>
        (XChaCha20Poly1305UnalignedHeaderSize + StorageConstants.SectorSize - 1) /
        StorageConstants.SectorSize * StorageConstants.SectorSize;
}
