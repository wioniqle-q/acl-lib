namespace Acl.Fs.Core.Resources;

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

    internal const string ConsistencyError = "Total read bytes ({0}) do not match file length (expected: {1}) for source file: {2}";
    internal const string ConsistencyErrorAudit = "Total read bytes ({0}) do not match file length (expected: {1}) for source file: {2}";

    internal const string ProcessedBytesExceeded = "Processed bytes ({0}) exceeded the original file size ({1}). Data corruption or logic error.";
    internal const string NegativeBytesToWrite = "Negative bytesToWrite value detected: {0}. Data corruption or logic error.";
    internal const string WrittenMoreBytesThanIntended = "Written more bytes ({0}) than intended file size ({1}). Data corruption or logic error.";
    internal const string BlockSizeExceedsPlaintextBuffer = "Block size ({0}) exceeds plaintext buffer length ({1}). Data corruption or logic error.";

    internal const string DecryptAndWriteBlockAsyncPrefix = "DecryptAndWriteBlockAsync: ";
    internal const string ProcessFileBlocksAsyncPrefix = "ProcessFileBlocksAsync: ";

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
    }
}