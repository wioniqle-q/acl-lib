namespace Acl.Fs.Native.Resource;

internal static class NativeErrorMessages
{
    internal const string FileHandleCannotBeNull = "File handle cannot be null.";
    internal const string FileHandleInvalid = "The file handle is invalid or has been marked as invalid.";
    internal const string HandleStaleOrInvalid = "The handle is stale or invalid.";
    internal const string FailedToFlushBuffers = "Failed to flush file buffers.";

    internal const string MemoryAddressCannotBeZero = "Memory address cannot be zero.";
    internal const string MemorySizeCannotBeZero = "Memory size cannot be zero.";
    internal const string FailedToLockMemoryPages = "Failed to lock memory pages.";
    internal const string FailedToUnlockMemoryPages = "Failed to unlock memory pages.";
}