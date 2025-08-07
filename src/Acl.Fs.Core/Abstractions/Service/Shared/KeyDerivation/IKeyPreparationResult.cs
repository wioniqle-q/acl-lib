namespace Acl.Fs.Core.Abstractions.Service.Shared.KeyDerivation;

internal interface IKeyPreparationResult : IDisposable
{
    ReadOnlySpan<byte> DerivedKey { get; }
    ReadOnlySpan<byte> Salt { get; }
}