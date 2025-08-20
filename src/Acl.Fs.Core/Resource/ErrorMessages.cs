namespace Acl.Fs.Core.Resource;

internal static class ErrorMessages
{
    internal const string SourcePathCannotBeNullOrInvalid = "Source path cannot be null or invalid.";
    internal const string DestinationPathCannotBeNullOrInvalid = "Destination path cannot be null or invalid.";

    internal const string InvalidKeySize = "Invalid key size. Key size must be 16, 24, or 32 bytes.";

    internal const string DecryptionFailed = "XChaCha20Poly1305 decryption failed - authentication failed";

    internal const string UnsupportedMajorVersion = "Unsupported major version: v{0}.{1}";
    internal const string VersionValidationFailed = "Version validation failed";

    internal const string FutureMajorVersionNotSupported =
        "Future major version {0}.{1} is not supported. Current supported major version is {2}.";

    internal const string FutureMinorVersionNotSupported =
        "Future minor version {0}.{1} is not supported. Current supported minor version for major version {0} is {2}.";

    internal const string InvalidVersionZeroZero =
        "Invalid version 0.0. Version cannot be zero for both major and minor components.";

    internal const string FailedToDeriveSalt = "Failed to derive salt for cryptographic operation.";
    internal const string FailedToDeriveNonce = "Failed to derive nonce for cryptographic operation.";
    internal const string HmacComputationFailed = "HMAC computation failed for cryptographic operation.";

    internal const string HeaderSaltMismatch =
        "Header salt does not match computed salt. Possible tampering or corruption detected.";
}