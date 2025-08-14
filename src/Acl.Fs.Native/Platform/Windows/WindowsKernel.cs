using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Acl.Fs.Native.Resource;
using Microsoft.Win32.SafeHandles;
using FileOps = Acl.Fs.Native.Platform.Windows.NativeInterop.FileOps;
using HandleOps = Acl.Fs.Native.Platform.Windows.NativeInterop.HandleOps;
using MemoryOps = Acl.Fs.Native.Platform.Windows.NativeInterop.MemoryOps;

namespace Acl.Fs.Native.Platform.Windows;

internal static class WindowsKernel
{
    private static readonly Func<SafeFileHandle, bool> FlushFileBuffers;
    private static readonly Func<IntPtr, nuint, bool> VirtualLockMemory;
    private static readonly Func<IntPtr, nuint, bool> VirtualUnlockMemory;

    static WindowsKernel()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            FlushFileBuffers = FlushFileBuffersInternal;
            VirtualLockMemory = VirtualLockInternal;
            VirtualUnlockMemory = VirtualUnlockInternal;
        }
        else
        {
            FlushFileBuffers = _ => false;
            VirtualLockMemory = (_, _) => false;
            VirtualUnlockMemory = (_, _) => false;
        }
    }

    internal static bool FlushBuffers(SafeFileHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle, NativeErrorMessages.FileHandleCannotBeNull);

        if (handle.IsClosed)
            return false;

        if (handle.IsInvalid)
            throw new InvalidOperationException(NativeErrorMessages.FileHandleInvalid);

        if (HandleOps.GetHandleInformation(handle, out _) is not true)
            throw new InvalidOperationException(NativeErrorMessages.HandleStaleOrInvalid);

        if (FlushFileBuffers(handle))
            return true;

        throw new Win32Exception(Marshal.GetLastWin32Error(), NativeErrorMessages.FailedToFlushBuffers);
    }

    internal static bool LockMemoryPages(IntPtr address, nuint size)
    {
        if (address == IntPtr.Zero)
            throw new ArgumentException(NativeErrorMessages.MemoryAddressCannotBeZero, nameof(address));

        if (size is 0)
            throw new ArgumentException(NativeErrorMessages.MemorySizeCannotBeZero, nameof(size));

        if (VirtualLockMemory(address, size))
            return true;

        var error = Marshal.GetLastWin32Error();
        throw new Win32Exception(error, $"{NativeErrorMessages.FailedToLockMemoryPages} Error: {error}");
    }

    internal static bool UnlockMemoryPages(IntPtr address, nuint size)
    {
        if (address == IntPtr.Zero)
            return false;

        if (size is 0)
            return false;

        if (VirtualUnlockMemory(address, size))
            return true;

        var error = Marshal.GetLastWin32Error();
        throw new Win32Exception(error, $"{NativeErrorMessages.FailedToUnlockMemoryPages} Error: {error}");
    }

    [SupportedOSPlatform("windows")]
    private static bool FlushFileBuffersInternal(SafeFileHandle handle)
    {
        return FileOps.FlushFileBuffers(handle);
    }

    [SupportedOSPlatform("windows")]
    private static bool VirtualLockInternal(IntPtr address, nuint size)
    {
        return MemoryOps.VirtualLock(address, size);
    }

    [SupportedOSPlatform("windows")]
    private static bool VirtualUnlockInternal(IntPtr address, nuint size)
    {
        return MemoryOps.VirtualUnlock(address, size);
    }
}