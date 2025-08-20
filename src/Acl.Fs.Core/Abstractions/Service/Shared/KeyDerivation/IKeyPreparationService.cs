namespace Acl.Fs.Core.Abstractions.Service.Shared.KeyDerivation;

internal interface IKeyPreparationService
{
    IKeyPreparationResult PrepareKey(ReadOnlySpan<byte> password);
    IKeyPreparationResult PrepareKeyWithSalt(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt);
}