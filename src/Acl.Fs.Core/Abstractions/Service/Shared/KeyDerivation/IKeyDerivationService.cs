namespace Acl.Fs.Core.Abstractions.Service.Shared.KeyDerivation;

internal interface IKeyDerivationService
{
    int SaltSize { get; }
    byte[] DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int outputLength);
}