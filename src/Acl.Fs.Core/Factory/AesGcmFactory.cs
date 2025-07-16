using System.Security.Cryptography;
using Acl.Fs.Core.Abstractions.Factory;
using Acl.Fs.Core.Resource;
using static Acl.Fs.Constant.Cryptography.KeyVaultConstants;

namespace Acl.Fs.Core.Factory;

internal sealed class AesGcmFactory : IAesGcmFactory
{
    public AesGcm Create(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key, nameof(key));

        if (key.Length is not (16 or 24 or 32))
            throw new ArgumentException(ErrorMessages.InvalidKeySize, nameof(key));

        return new AesGcm(key, TagSize);
    }
}