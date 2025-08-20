using System.Security.Cryptography;

namespace Acl.Fs.Core.Abstractions.Factory;

internal interface IChaCha20Poly1305Factory
{
    ChaCha20Poly1305 Create(ReadOnlySpan<byte> key);
}