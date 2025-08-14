namespace Acl.Fs.Core.Resource;

internal static class AuditMessages
{
    internal const string EncryptionProcessStarted = "Encryption process started";

    internal const string InputStreamOpened = "Input stream opened";
    internal const string OutputStreamOpened = "Output stream opened";

    internal const string HeaderPrepared = "Header prepared";
    internal const string HeaderWritten = "Header written";

    internal const string EncryptionProcessCompleted = "Encryption process completed successfully";
    internal const string EncryptionFailed = "Encryption failed";
    internal const string BlockEncryptionFailed = "Block encryption failed";

    internal const string DecryptionProcessStarted = "Decryption process started";
    internal const string DecryptionProcessCompleted = "Decryption process completed";

    internal const string DecryptionHeaderRead = "Decryption header read";

    internal const string DecryptionFailed = "Decryption failed";
    internal const string BlockDecryptionFailed = "Block decryption failed";

    internal const string ConsistencyErrorAudit =
        "Total read bytes ({0}) do not match file length (expected: {1})";

    internal const string ProcessedBytesExceeded =
        "Processed bytes ({0}) exceeded the original file size ({1}). Data corruption or logic error.";

    internal const string NegativeBytesToWrite =
        "Negative bytesToWrite value detected: {0}. Data corruption or logic error.";

    internal const string WrittenMoreBytesThanIntended =
        "Written more bytes ({0}) than intended file size ({1}). Data corruption or logic error.";

    internal const string BlockSizeExceedsPlaintextBuffer =
        "Block size ({0}) exceeds plaintext buffer length ({1}). Data corruption or logic error.";

    internal const string ProcessFileBlocksAsyncPrefix = "ProcessFileBlocksAsync: ";

    internal const string MemoryLockAttempted =
        "Attempting to lock memory pages at address {Address} with size {Size} bytes";

    internal const string MemoryLockSucceeded =
        "Successfully locked memory pages at address {Address} with size {Size} bytes";

    internal const string MemoryLockFailed =
        "Failed to lock memory pages at address {Address} with size {Size} bytes: {Error}";

    internal const string MemoryUnlockAttempted =
        "Attempting to unlock memory pages at address {Address} with size {Size} bytes";

    internal const string MemoryUnlockSucceeded =
        "Successfully unlocked memory pages at address {Address} with size {Size} bytes";

    internal const string MemoryUnlockFailed =
        "Failed to unlock memory pages at address {Address} with size {Size} bytes: {Error}";

    internal const string MemoryHandleNotAllocated = "Memory operation skipped: GCHandle is not allocated";

    internal const string MemoryNonWindowsPlatform =
        "Memory locking not supported on non-Windows platforms, returning success";

    internal const string HandleNotAllocatedReason = "Handle not allocated";
    internal const string UnknownAddressReason = "Unknown";

    internal static class ContextKeys
    {
        internal const string Algorithm = "Algorithm";
        internal const string InputFile = "InputFile";
        internal const string OutputFile = "OutputFile";
        internal const string ExceptionType = "ExceptionType";
        internal const string ExceptionMessage = "ExceptionMessage";
        internal const string StackTrace = "StackTrace";
        internal const string BlockIndex = "BlockIndex";
        internal const string TotalBytesRead = "TotalBytesRead";
        internal const string StreamLength = "StreamLength";
        internal const string Handle = "Handle";
        internal const string Size = "Size";
        internal const string Reason = "Reason";
        internal const string Platform = "Platform";
        internal const string Address = "Address";
        internal const string Error = "Error";
    }
}