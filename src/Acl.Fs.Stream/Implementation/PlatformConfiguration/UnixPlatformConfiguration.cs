using Acl.Fs.Native.Platform.Unix;
using Acl.Fs.Stream.Abstractions.Implementation.PlatformConfiguration;
using Acl.Fs.Stream.Resource;
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

        logger?.LogDebug(LogMessages.UnixConfiguration);
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
            logger?.LogWarning(LogMessages.PosixFadviseSequentialFailed,
                seqResult, fileStream.Length);

        var dontNeedResult = UnixKernel.PosixFadvise(fileStream.SafeFileHandle, 0, fileStream.Length,
            UnixConstants.FileAdvice.PosixFadvDontNeed);
        if (dontNeedResult is not 0)
            logger?.LogWarning(LogMessages.PosixFadviseDontNeedFailed,
                dontNeedResult, fileStream.Length);
    }

    private static bool TrySetIoPriority(int priority)
    {
        return UnixKernel.SetIoPriority(UnixConstants.IoPriority.WhoProcess, 0, priority, 0) is 0;
    }
}