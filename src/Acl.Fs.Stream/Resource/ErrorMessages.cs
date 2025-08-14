namespace Acl.Fs.Stream.Resource;

internal static class ErrorMessages
{
    internal const string UnsupportedPlatform =
        "The platform '{0}' is not supported by the '{1}' implementation.";

    internal const string UnixFsyncFailed = "fsync failed with error: {0}";
    internal const string MacOsFullFsyncFailed = "Full fsync failed with error: {0}";
    internal const string WindowsFlushBuffersFailed = "FlushFileBuffers failed with error: {0}";
}