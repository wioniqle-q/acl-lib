using System.Runtime.Versioning;
using Acl.Fs.Native.Platform.Windows.NativeInterop;

namespace Acl.Fs.Native.Platform.Windows.Extensions;

[SupportedOSPlatform("windows")]
internal static class ShellExtensions
{
    internal static void ShChangeNotify(string path)
    {
        Shell32.SHChangeNotify(Shell32.Shcne.ShcneUpdateitem, Shell32.Shcnf.ShcnfPathw, path);
    }
}