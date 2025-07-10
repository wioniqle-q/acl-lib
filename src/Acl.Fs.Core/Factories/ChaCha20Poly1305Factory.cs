using System.Security.Cryptography;
using Acl.Fs.Core.Interfaces.Factory;
using Acl.Fs.Core.Resources;

namespace Acl.Fs.Core.Factories;

internal sealed class ChaCha20Poly1305Factory : IChaCha20Poly1305Factory
{
    public ChaCha20Poly1305 Create(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key, nameof(key));

        if (key.Length is 0 or not 32)
            throw new ArgumentException(ErrorMessages.InvalidKeySize, nameof(key));

        return new ChaCha20Poly1305(key);
    }
}