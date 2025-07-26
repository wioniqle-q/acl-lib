using Acl.Fs.Constant.Versioning;
using Acl.Fs.Core.Abstractions;
using Acl.Fs.Core.Resource;
using Acl.Fs.Core.Versioning.Exceptions;

namespace Acl.Fs.Core.Versioning.ValidationStrategies;

internal sealed class V0ValidationStrategy : IVersionValidationStrategy
{
    public void Validate(byte minorVersion)
    {
        // For beta version 0.x, minor versions 1, 2, 3, and 4 are currently supported
        // v0.1.x: Initial release with AES-GCM and ChaCha20Poly1305
        // v0.2.x: Release with XChaCha20Poly1305 support (broken nonce handling - incompatible)
        // v0.3.x: Fixed XChaCha20Poly1305 nonce size handling
        // v0.4.x: Enhanced salt generation with HMAC-SHA512 (64-byte salt instead of 32-byte)
        if (minorVersion > VersionConstants.CurrentMinorVersion)
            throw new VersionValidationException(
                string.Format(ErrorMessages.FutureMinorVersionNotSupported,
                    0, minorVersion, VersionConstants.CurrentMinorVersion));
    }
}