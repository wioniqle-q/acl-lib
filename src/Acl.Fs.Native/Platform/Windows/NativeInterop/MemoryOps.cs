using System.Runtime.InteropServices;

namespace Acl.Fs.Native.Platform.Windows.NativeInterop;

internal static partial class MemoryOps
{
    [LibraryImport(WindowsConstants.Libraries.Kernel32LibraryName, EntryPoint = "VirtualLock",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool VirtualLock(IntPtr lpAddress, nuint dwSize);

    [LibraryImport(WindowsConstants.Libraries.Kernel32LibraryName, EntryPoint = "VirtualUnlock",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool VirtualUnlock(IntPtr lpAddress, nuint dwSize);
}