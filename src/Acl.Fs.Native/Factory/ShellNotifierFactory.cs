using Acl.Fs.Native.Platform.Windows.Extensions;

namespace Acl.Fs.Native.Factory;

internal static class ShellNotifierFactory
{
    internal static void NotifyPathUpdated(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (OperatingSystem.IsWindows())
            ShellExtensions.ShChangeNotify(path);
    }
}