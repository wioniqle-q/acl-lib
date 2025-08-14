using Acl.Fs.Stream.Abstractions.Implementation.PlatformConfiguration;
using Acl.Fs.Stream.Resource;
using Microsoft.Extensions.Logging;

namespace Acl.Fs.Stream.Implementation.PlatformConfiguration;

internal sealed class MacOsPlatformConfiguration(ILogger? logger = null) : IPlatformConfiguration
{
    private static readonly Lazy<bool> ProcessConfigured =
        new(ConfigureProcess, LazyThreadSafetyMode.ExecutionAndPublication);

    public void ConfigureStream(System.IO.Stream stream)
    {
        _ = ProcessConfigured.Value;

        ConfigureFileSpecificSettings(stream);

        logger?.LogDebug(LogMessages.MacOsConfiguration);
    }

    private static bool ConfigureProcess()
    {
        return true;
    }

    private void ConfigureFileSpecificSettings(System.IO.Stream stream)
    {
        if (stream is not FileStream fileStream) return;
        logger?.LogDebug(LogMessages.FileSpecificSettingsConfigured, fileStream.Name);
    }
}