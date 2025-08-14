using System.Runtime.InteropServices;

namespace Acl.Fs.Native.Platform.Windows.NativeInterop;

internal static partial class Shell32
{
    [LibraryImport(WindowsConstants.Libraries.Shell32LibraryName, StringMarshalling = StringMarshalling.Utf16)]
    internal static partial void SHChangeNotify(Shcne wEventId, Shcnf uFlags,
        [MarshalAs(UnmanagedType.LPWStr)] string dwItem1, nuint dwItem2 = 0);

    internal enum Shcne : uint
    {
        ShcneUpdateitem = 0x00002000
    }

    internal enum Shcnf : uint
    {
        ShcnfPathw = 0x0005
    }
}