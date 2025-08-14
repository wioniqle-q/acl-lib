using Acl.Fs.Core.Abstractions.Factory;
using Acl.Fs.Core.Resource;
using NSec.Cryptography;

namespace Acl.Fs.Core.Factory;

internal sealed class XChaCha20Poly1305Factory : IXChaCha20Poly1305Factory
{
    public XChaCha20Poly1305 Create(ReadOnlySpan<byte> key)
    {
        return key.Length is not 32
            ? throw new ArgumentException(ErrorMessages.InvalidKeySize, nameof(key))
            : new XChaCha20Poly1305();
    }
}