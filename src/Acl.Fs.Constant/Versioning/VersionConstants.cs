using Acl.Fs.Constant.Cryptography;
using Acl.Fs.Constant.Storage;

namespace Acl.Fs.Constant.Versioning;

internal static class VersionConstants
{
    internal const byte CurrentMajorVersion = 1;
    internal const byte CurrentMinorVersion = 0;

    internal const int VersionHeaderSize = 2;

    internal static int UnalignedHeaderSize =>
        VersionHeaderSize + KeyVaultConstants.NonceSize + sizeof(long) + KeyVaultConstants.SaltSize;

    internal static int HeaderSize => (UnalignedHeaderSize + StorageConstants.SectorSize - 1) /
        StorageConstants.SectorSize * StorageConstants.SectorSize;
}