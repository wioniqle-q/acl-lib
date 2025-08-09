namespace Acl.Fs.Stream.Resource;

internal static class LogMessages
{
    internal const string UnixConfiguration = "Configuring Unix-specific stream properties";
    internal const string MacOsConfiguration = "Configuring macOS-specific stream properties";
    internal const string WindowsConfiguration = "Configuring Windows-specific stream properties";
    internal const string FileSpecificSettingsConfigured = "File-specific settings configured for {FileName}";

    internal const string PosixFadviseSequentialFailed =
        "PosixFadvise Sequential failed with error {ErrorCode} for file length {Length}";

    internal const string PosixFadviseDontNeedFailed =
        "PosixFadvise DontNeed failed with error {ErrorCode} for file length {Length}";
}