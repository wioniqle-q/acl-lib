using System.Collections.Frozen;
using System.Runtime.InteropServices;
using Acl.Fs.Audit.Abstractions;
using Acl.Fs.Audit.Category;
using Acl.Fs.Audit.Constant;
using Acl.Fs.Audit.Extensions;
using Acl.Fs.Core.Resource;
using Acl.Fs.Native.Platform.Windows;

namespace Acl.Fs.Core.Utility;

internal static class MemoryOperations
{
    internal static bool LockMemory(this GCHandle handle, int size, IAuditLogger? auditLogger = null)
    {
        if (handle.IsAllocated is not true)
        {
            auditLogger?.Audit(
                AuditCategory.MemoryManagement,
                AuditMessages.MemoryHandleNotAllocated,
                AuditEventIds.MemoryLockFailed,
                new Dictionary<string, object?>
                {
                    [AuditMessages.ContextKeys.Handle] = handle.ToString(),
                    [AuditMessages.ContextKeys.Size] = size,
                    [AuditMessages.ContextKeys.Reason] = AuditMessages.HandleNotAllocatedReason
                }.ToFrozenDictionary());
            return false;
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            var address = IntPtr.Zero;
            try
            {
                address = handle.AddrOfPinnedObject();

                auditLogger?.Audit(
                    AuditCategory.MemoryManagement,
                    AuditMessages.MemoryLockAttempted,
                    AuditEventIds.MemoryLockAttempted,
                    new Dictionary<string, object?>
                    {
                        [AuditMessages.ContextKeys.Address] = $"0x{address:X}",
                        [AuditMessages.ContextKeys.Size] = size
                    }.ToFrozenDictionary());

                var result = WindowsKernel.LockMemoryPages(address, (nuint)size);

                if (result)
                    auditLogger?.Audit(
                        AuditCategory.MemoryManagement,
                        AuditMessages.MemoryLockSucceeded,
                        AuditEventIds.MemoryLockSucceeded,
                        new Dictionary<string, object?>
                        {
                            [AuditMessages.ContextKeys.Address] = $"0x{address:X}",
                            [AuditMessages.ContextKeys.Size] = size
                        }.ToFrozenDictionary());

                return result;
            }
            catch (Exception ex)
            {
                auditLogger?.Audit(
                    AuditCategory.MemoryManagement,
                    AuditMessages.MemoryLockFailed,
                    AuditEventIds.MemoryLockFailed,
                    new Dictionary<string, object?>
                    {
                        [AuditMessages.ContextKeys.Address] = address != IntPtr.Zero
                            ? $"0x{address:X}"
                            : AuditMessages.UnknownAddressReason,
                        [AuditMessages.ContextKeys.Size] = size,
                        [AuditMessages.ContextKeys.Error] = ex.Message,
                        [AuditMessages.ContextKeys.ExceptionType] = ex.GetType().Name
                    }.ToFrozenDictionary());
                return false;
            }
        }

        auditLogger?.Audit(
            AuditCategory.MemoryManagement,
            AuditMessages.MemoryNonWindowsPlatform,
            AuditEventIds.MemoryLockSucceeded,
            new Dictionary<string, object?>
            {
                [AuditMessages.ContextKeys.Platform] = RuntimeInformation.OSDescription,
                [AuditMessages.ContextKeys.Size] = size
            }.ToFrozenDictionary());

        return true;
    }

    internal static bool UnlockMemory(this GCHandle handle, int size, IAuditLogger? auditLogger = null)
    {
        if (handle.IsAllocated is not true)
        {
            auditLogger?.Audit(
                AuditCategory.MemoryManagement,
                AuditMessages.MemoryHandleNotAllocated,
                AuditEventIds.MemoryUnlockFailed,
                new Dictionary<string, object?>
                {
                    [AuditMessages.ContextKeys.Handle] = handle.ToString(),
                    [AuditMessages.ContextKeys.Size] = size,
                    [AuditMessages.ContextKeys.Reason] = AuditMessages.HandleNotAllocatedReason
                }.ToFrozenDictionary());
            return false;
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            var address = IntPtr.Zero;
            try
            {
                address = handle.AddrOfPinnedObject();

                auditLogger?.Audit(
                    AuditCategory.MemoryManagement,
                    AuditMessages.MemoryUnlockAttempted,
                    AuditEventIds.MemoryUnlockAttempted,
                    new Dictionary<string, object?>
                    {
                        [AuditMessages.ContextKeys.Address] = $"0x{address:X}",
                        [AuditMessages.ContextKeys.Size] = size
                    }.ToFrozenDictionary());

                var result = WindowsKernel.UnlockMemoryPages(address, (nuint)size);

                if (result)
                    auditLogger?.Audit(
                        AuditCategory.MemoryManagement,
                        AuditMessages.MemoryUnlockSucceeded,
                        AuditEventIds.MemoryUnlockSucceeded,
                        new Dictionary<string, object?>
                        {
                            [AuditMessages.ContextKeys.Address] = $"0x{address:X}",
                            [AuditMessages.ContextKeys.Size] = size
                        }.ToFrozenDictionary());

                return result;
            }
            catch (Exception ex)
            {
                auditLogger?.Audit(
                    AuditCategory.MemoryManagement,
                    AuditMessages.MemoryUnlockFailed,
                    AuditEventIds.MemoryUnlockFailed,
                    new Dictionary<string, object?>
                    {
                        [AuditMessages.ContextKeys.Address] = address != IntPtr.Zero
                            ? $"0x{address:X}"
                            : AuditMessages.UnknownAddressReason,
                        [AuditMessages.ContextKeys.Size] = size,
                        [AuditMessages.ContextKeys.Error] = ex.Message,
                        [AuditMessages.ContextKeys.ExceptionType] = ex.GetType().Name
                    }.ToFrozenDictionary());
                return false;
            }
        }

        auditLogger?.Audit(
            AuditCategory.MemoryManagement,
            AuditMessages.MemoryNonWindowsPlatform,
            AuditEventIds.MemoryUnlockSucceeded,
            new Dictionary<string, object?>
            {
                [AuditMessages.ContextKeys.Platform] = RuntimeInformation.OSDescription,
                [AuditMessages.ContextKeys.Size] = size
            }.ToFrozenDictionary());

        return true;
    }
}