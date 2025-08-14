namespace Acl.Fs.Audit.Constant;

internal static class AuditEventIds
{
    internal const int EncryptionStarted = 100;
    internal const int EncryptionInputOpened = 101;
    internal const int EncryptionOutputOpened = 102;
    internal const int EncryptionHeaderPrepared = 110;
    internal const int EncryptionHeaderWritten = 111;
    internal const int BlockEncryptionFailed = 122;
    internal const int EncryptionCompleted = 130;
    internal const int EncryptionError = 190;

    internal const int DecryptionStarted = 200;
    internal const int DecryptionInputOpened = 201;
    internal const int DecryptionOutputOpened = 202;
    internal const int DecryptionHeaderRead = 210;
    internal const int BlockDecryptionFailed = 222;
    internal const int DecryptionCompleted = 230;
    internal const int DecryptionError = 290;

    internal const int MemoryLockAttempted = 300;
    internal const int MemoryLockSucceeded = 301;
    internal const int MemoryLockFailed = 302;
    internal const int MemoryUnlockAttempted = 310;
    internal const int MemoryUnlockSucceeded = 311;
    internal const int MemoryUnlockFailed = 312;
}