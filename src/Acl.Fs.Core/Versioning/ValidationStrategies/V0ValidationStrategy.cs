using Acl.Fs.Constant.Versioning;
using Acl.Fs.Core.Abstractions;
using Acl.Fs.Core.Resource;
using Acl.Fs.Core.Versioning.Exceptions;

namespace Acl.Fs.Core.Versioning.ValidationStrategies;

internal sealed class V0ValidationStrategy : IVersionValidationStrategy
{
    public void Validate(byte minorVersion)
    {
        // For beta version 0.x, only minor version 1 is currently supported
        if (minorVersion > VersionConstants.CurrentMinorVersion)
            throw new VersionValidationException(
                string.Format(ErrorMessages.FutureMinorVersionNotSupported,
                    0, minorVersion, VersionConstants.CurrentMinorVersion));
    }
}