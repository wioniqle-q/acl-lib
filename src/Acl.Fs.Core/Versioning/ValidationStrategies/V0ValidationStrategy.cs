using Acl.Fs.Constant.Versioning;
using Acl.Fs.Core.Abstractions;
using Acl.Fs.Core.Resource;
using Acl.Fs.Core.Versioning.Exceptions;

namespace Acl.Fs.Core.Versioning.ValidationStrategies;

internal sealed class V0ValidationStrategy : IVersionValidationStrategy
{
    public void Validate(byte minorVersion)
    {
        // For beta version 0.x, minor versions 1 are currently supported
        // v0.1.x: Initial release with AES-GCM, ChaCha20Poly1305 and XChaCha20Poly1305 support
        if (minorVersion > VersionConstants.CurrentMinorVersion)
            throw new VersionValidationException(
                string.Format(ErrorMessages.FutureMinorVersionNotSupported,
                    0, minorVersion, VersionConstants.CurrentMinorVersion));
    }
}