using Acl.Fs.Constant.Versioning;
using Acl.Fs.Core.Abstractions;
using Acl.Fs.Core.Resource;
using Acl.Fs.Core.Versioning.Exceptions;

namespace Acl.Fs.Core.Versioning.ValidationStrategies;

internal sealed class V0ValidationStrategy : IVersionValidationStrategy
{
    public void Validate(byte minorVersion)
    {
        // For beta version 0.x, minor versions 1-7 are currently supported
        // v0.1.x: Initial release with AES-GCM, ChaCha20Poly1305 and XChaCha20Poly1305 support
        // v0.2.x: Added dynamic salt size support and cross-platform shell notifications
        // v0.3.x: Platform-specific configuration and process-level optimizations
        // v0.4.x: Key preparation service refactoring 
        // v0.5.x: Password parameters refactored to use ReadOnlyMemory<byte> with disposal
        // v0.6.x: Nonce parameters refactored to use ReadOnlyMemory<byte> 
        // v0.7.x: Salt validation logic into ValidateHeaderSalt() method
        if (minorVersion > VersionConstants.CurrentMinorVersion)
            throw new VersionValidationException(
                string.Format(ErrorMessages.FutureMinorVersionNotSupported,
                    0, minorVersion, VersionConstants.CurrentMinorVersion));
    }
}