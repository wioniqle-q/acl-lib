using System.Runtime.InteropServices;
using Acl.Fs.Stream.Abstractions.Implementation.PlatformConfiguration;
using Acl.Fs.Stream.Implementation.PlatformConfiguration;
using Acl.Fs.Stream.Resource;
using Microsoft.Extensions.Logging;

namespace Acl.Fs.Stream.Core;

internal static class PlatformConfigurationFactory
{
    public static IPlatformConfiguration Create(ILogger logger)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return new WindowsPlatformConfiguration(logger);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            return new MacOsPlatformConfiguration(logger);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            return new UnixPlatformConfiguration(logger);

        throw new PlatformNotSupportedException(
            string.Format(ErrorMessages.UnsupportedPlatform, RuntimeInformation.OSDescription,
                nameof(PlatformConfigurationFactory)));
    }
}