namespace Acl.Fs.Core.Abstractions.Service.Shared.KeyDerivation;

internal interface IKeyPreparationService
{
    IKeyPreparationResult PrepareKey(ReadOnlySpan<byte> sourceKey);
    IKeyPreparationResult PrepareKeyWithSalt(ReadOnlySpan<byte> sourceKey, ReadOnlySpan<byte> salt);
}