using System.Runtime.Versioning;
using Acl.Fs.Native.Platform.Windows.NativeInterop;

namespace Acl.Fs.Native.Platform.Windows.Extensions;

[SupportedOSPlatform("windows")]
internal static class ShellExtensions
{
    private static void ShChangeNotifySingle(string path, Shell32.Shcne eventId)
    {
        Shell32.SHChangeNotify(eventId,
            Shell32.Shcnf.ShcnfPathw | Shell32.Shcnf.ShcnfFlushNoWait | Shell32.Shcnf.ShcnfNotifyrecursive, path);
    }

    internal static void ShChangeNotify(string filePath)
    {
        if (string.IsNullOrEmpty(filePath))
            return;

        ShChangeNotifySingle(filePath, Shell32.Shcne.ShcneUpdateitem);

        var parentDir = Path.GetDirectoryName(filePath);
        if (string.IsNullOrEmpty(parentDir) is not true)
            ShChangeNotifySingle(parentDir, Shell32.Shcne.ShcneUpdatedir);
    }
}