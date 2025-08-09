using Acl.Fs.Stream.Abstractions;
using Microsoft.Extensions.Logging;

namespace Acl.Fs.Stream.Implementation.PlatformConfiguration;

internal sealed class WindowsPlatformConfiguration(ILogger? logger = null) : IPlatformConfiguration
{
    private static readonly Lazy<bool> ProcessConfigured =
        new(ConfigureProcess, LazyThreadSafetyMode.ExecutionAndPublication);

    public void ConfigureStream(System.IO.Stream stream)
    {
        _ = ProcessConfigured.Value;

        ConfigureFileSpecificSettings(stream);

        logger?.LogDebug("Windows stream configuration applied");
    }

    private static bool ConfigureProcess()
    {
        return true;
    }

    private void ConfigureFileSpecificSettings(System.IO.Stream stream)
    {
        if (stream is not FileStream fileStream) return;

        logger?.LogDebug("File-specific settings configured for {FileName}", fileStream.Name);
    }
}