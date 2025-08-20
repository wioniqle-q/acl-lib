using Acl.Fs.Constant.Cryptography;
using Acl.Fs.Core.Abstractions.Service.Shared.KeyDerivation;
using NSec.Cryptography;

namespace Acl.Fs.Core.Service.Shared.KeyDerivation;

internal sealed class Argon2KeyDerivationService : IKeyDerivationService
{
    private static readonly Argon2id Algorithm = new(new Argon2Parameters
    {
        DegreeOfParallelism = CryptoConstants.Argon2IdDegreeOfParallelism,
        MemorySize = CryptoConstants.Argon2IdMemorySize,
        NumberOfPasses = CryptoConstants.Argon2IdNumberOfPasses
    });

    public byte[] DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int outputLength)
    {
        var derivedKey = new byte[outputLength];

        Span<byte> argon2Salt = stackalloc byte[SaltSize];
        salt.CopyTo(argon2Salt);

        Algorithm.DeriveBytes(
            password,
            argon2Salt,
            derivedKey.AsSpan());

        return derivedKey;
    }

    public int SaltSize => Algorithm.MaxSaltSize;
}