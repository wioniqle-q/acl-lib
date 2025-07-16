using Acl.Fs.Core.Abstractions;

namespace Acl.Fs.Core.Versioning.ValidationStrategies;

internal sealed class V1ValidationStrategy : IVersionValidationStrategy
{
    public void Validate(byte minorVersion)
    {
    }
}