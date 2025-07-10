using System.Security.Cryptography;
using Acl.Fs.Core.Interfaces.Factory;
using Acl.Fs.Core.Resources;
using static Acl.Fs.Abstractions.Constants.KeyVaultConstants;

namespace Acl.Fs.Core.Factories;

internal sealed class AesGcmFactory : IAesGcmFactory
{
    public AesGcm Create(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key, nameof(key));

        if (key.Length is not 32)
            throw new ArgumentException(ErrorMessages.InvalidKeySize, nameof(key));

        return new AesGcm(key, TagSize);
    }
}