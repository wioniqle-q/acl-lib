using System.Security.Cryptography;
using Acl.Fs.Core.Abstractions.Factory;
using Acl.Fs.Core.Resource;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.Factory;

internal sealed class AesGcmFactory : IAesGcmFactory
{
    public AesGcm Create(ReadOnlySpan<byte> key)
    {
        return key.Length is not 32
            ? throw new ArgumentException(ErrorMessages.InvalidKeySize, nameof(key))
            : new AesGcm(key, TagSize);
    }
}