using Acl.Fs.Core.Abstractions.Service.Shared.KeyDerivation;

namespace Acl.Fs.Core.Service.Shared.KeyDerivation;

internal sealed class KeyPreparationService(IKeyDerivationService keyDerivationService) : IKeyPreparationService
{
    private readonly IKeyDerivationService _keyDerivationService =
        keyDerivationService ?? throw new ArgumentNullException(nameof(keyDerivationService));

    public IKeyPreparationResult PrepareKey(ReadOnlySpan<byte> sourceKey)
    {
        return new KeyPreparationResult(_keyDerivationService, sourceKey);
    }

    public IKeyPreparationResult PrepareKeyWithSalt(ReadOnlySpan<byte> sourceKey, ReadOnlySpan<byte> salt)
    {
        return new KeyPreparationResult(_keyDerivationService, sourceKey, salt);
    }
}