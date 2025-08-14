using System.Security.Cryptography;
using Acl.Fs.Core.Abstractions.Factory;
using Acl.Fs.Core.Resource;

namespace Acl.Fs.Core.Factory;

internal sealed class ChaCha20Poly1305Factory : IChaCha20Poly1305Factory
{
    public ChaCha20Poly1305 Create(ReadOnlySpan<byte> key)
    {
        return key.Length is not 32
            ? throw new ArgumentException(ErrorMessages.InvalidKeySize, nameof(key))
            : new ChaCha20Poly1305(key);
    }
}