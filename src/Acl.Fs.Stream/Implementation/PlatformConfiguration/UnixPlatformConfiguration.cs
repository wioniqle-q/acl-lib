using Acl.Fs.Native.Platform.Unix;
using Acl.Fs.Stream.Abstractions;
using Microsoft.Extensions.Logging;

namespace Acl.Fs.Stream.Implementation.PlatformConfiguration;

internal sealed class UnixPlatformConfiguration(ILogger? logger = null) : IPlatformConfiguration
{
    private static readonly Lazy<bool> ProcessConfigured =
        new(ConfigureProcess, LazyThreadSafetyMode.ExecutionAndPublication);

    public void ConfigureStream(System.IO.Stream stream)
    {
        _ = ProcessConfigured.Value;

        ConfigureFileSpecificSettings(stream);

        logger?.LogDebug("Unix stream configuration applied");
    }

    private static bool ConfigureProcess()
    {
        return TrySetIoPriority(UnixConstants.IoPriority.ClassRealTime) ||
               TrySetIoPriority(UnixConstants.IoPriority.ClassBestEffort);
    }

    private void ConfigureFileSpecificSettings(System.IO.Stream stream)
    {
        if (stream is not FileStream fileStream) return;

        var seqResult = UnixKernel.PosixFadvise(fileStream.SafeFileHandle, 0, fileStream.Length,
            UnixConstants.FileAdvice.PosixFadvSequential);
        if (seqResult is not 0)
            logger?.LogWarning("PosixFadvise Sequential failed with error {ErrorCode} for file length {Length}",
                seqResult, fileStream.Length);

        var dontNeedResult = UnixKernel.PosixFadvise(fileStream.SafeFileHandle, 0, fileStream.Length,
            UnixConstants.FileAdvice.PosixFadvDontNeed);
        if (dontNeedResult is not 0)
            logger?.LogWarning("PosixFadvise DontNeed failed with error {ErrorCode} for file length {Length}",
                dontNeedResult, fileStream.Length);
    }

    private static bool TrySetIoPriority(int priority)
    {
        return UnixKernel.SetIoPriority(UnixConstants.IoPriority.WhoProcess, 0, priority, 0) is 0;
    }
}