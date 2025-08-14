using NSec.Cryptography;

namespace Acl.Fs.Core.Abstractions.Factory;

internal interface IXChaCha20Poly1305Factory
{
    XChaCha20Poly1305 Create(ReadOnlySpan<byte> key);
}