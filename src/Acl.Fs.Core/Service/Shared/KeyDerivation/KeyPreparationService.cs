using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Acl.Fs.Audit.Abstractions;
using Acl.Fs.Constant.Cryptography;
using Acl.Fs.Core.Abstractions.Service.Shared.KeyDerivation;
using Acl.Fs.Core.Pool;
using Acl.Fs.Core.Utility;

namespace Acl.Fs.Core.Service.Shared.KeyDerivation;

internal sealed class KeyPreparationService(
    IKeyDerivationService keyDerivationService,
    IAuditLogger auditLogger) : IKeyPreparationService
{
    private readonly IAuditLogger _auditLogger = auditLogger ?? throw new ArgumentNullException(nameof(auditLogger));

    private readonly IKeyDerivationService _keyDerivationService =
        keyDerivationService ?? throw new ArgumentNullException(nameof(keyDerivationService));

    public IKeyPreparationResult PrepareKey(ReadOnlySpan<byte> sourceKey)
    {
        var pooledSaltBuffer = CryptoPool.Rent(_keyDerivationService.SaltSize);

        byte[] derivedKeyData = [];
        byte[] saltData = [];
        GCHandle pinnedKeyHandle = default;
        GCHandle pinnedSaltHandle = default;
        var isKeyMemoryLocked = 0;
        var isSaltMemoryLocked = 0;

        try
        {
            RandomNumberGenerator.Fill(pooledSaltBuffer.AsSpan(0, _keyDerivationService.SaltSize));

            saltData = pooledSaltBuffer.AsSpan(0, _keyDerivationService.SaltSize).ToArray();

            derivedKeyData = _keyDerivationService.DeriveKey(
                sourceKey,
                pooledSaltBuffer.AsSpan(0, _keyDerivationService.SaltSize),
                CryptoConstants.Argon2IdOutputKeyLength);

            pinnedKeyHandle = GCHandle.Alloc(derivedKeyData, GCHandleType.Pinned);
            if (pinnedKeyHandle.LockMemory(derivedKeyData.Length, _auditLogger))
                Interlocked.Exchange(ref isKeyMemoryLocked, 1);

            pinnedSaltHandle = GCHandle.Alloc(saltData, GCHandleType.Pinned);
            if (pinnedSaltHandle.LockMemory(saltData.Length, _auditLogger))
                Interlocked.Exchange(ref isSaltMemoryLocked, 1);

            var derivedKeyMemory = new ReadOnlyMemory<byte>(derivedKeyData);
            var saltMemory = new ReadOnlyMemory<byte>(saltData);

            return new KeyPreparationResult(
                derivedKeyMemory,
                saltMemory,
                pinnedKeyHandle,
                pinnedSaltHandle,
                isKeyMemoryLocked,
                isSaltMemoryLocked,
                _auditLogger);
        }
        catch
        {
            if (Interlocked.CompareExchange(ref isKeyMemoryLocked, 0, 1) is 1)
                pinnedKeyHandle.UnlockMemory(derivedKeyData.Length, _auditLogger);
            if (pinnedKeyHandle.IsAllocated)
                pinnedKeyHandle.Free();

            if (Interlocked.CompareExchange(ref isSaltMemoryLocked, 0, 1) is 1)
                pinnedSaltHandle.UnlockMemory(saltData.Length, _auditLogger);
            if (pinnedSaltHandle.IsAllocated)
                pinnedSaltHandle.Free();

            CryptographicOperations.ZeroMemory(derivedKeyData);
            CryptographicOperations.ZeroMemory(saltData);

            throw;
        }
        finally
        {
            CryptoPool.Return(pooledSaltBuffer);
        }
    }

    public IKeyPreparationResult PrepareKeyWithSalt(ReadOnlySpan<byte> sourceKey, ReadOnlySpan<byte> salt)
    {
        var derivedKeyData = _keyDerivationService.DeriveKey(
            sourceKey,
            salt,
            CryptoConstants.Argon2IdOutputKeyLength);

        byte[] saltData = [];
        GCHandle pinnedKeyHandle = default;
        GCHandle pinnedSaltHandle = default;
        var isKeyMemoryLocked = 0;
        var isSaltMemoryLocked = 0;

        try
        {
            saltData = salt.ToArray();

            pinnedKeyHandle = GCHandle.Alloc(derivedKeyData, GCHandleType.Pinned);
            if (pinnedKeyHandle.LockMemory(derivedKeyData.Length, _auditLogger))
                Interlocked.Exchange(ref isKeyMemoryLocked, 1);

            pinnedSaltHandle = GCHandle.Alloc(saltData, GCHandleType.Pinned);
            if (pinnedSaltHandle.LockMemory(saltData.Length, _auditLogger))
                Interlocked.Exchange(ref isSaltMemoryLocked, 1);

            var derivedKeyMemory = new ReadOnlyMemory<byte>(derivedKeyData);
            var saltMemory = new ReadOnlyMemory<byte>(saltData);

            return new KeyPreparationResult(
                derivedKeyMemory,
                saltMemory,
                pinnedKeyHandle,
                pinnedSaltHandle,
                isKeyMemoryLocked,
                isSaltMemoryLocked,
                _auditLogger);
        }
        catch
        {
            if (Interlocked.CompareExchange(ref isKeyMemoryLocked, 0, 1) is 1)
                pinnedKeyHandle.UnlockMemory(derivedKeyData.Length, _auditLogger);
            if (pinnedKeyHandle.IsAllocated)
                pinnedKeyHandle.Free();

            if (Interlocked.CompareExchange(ref isSaltMemoryLocked, 0, 1) is 1)
                pinnedSaltHandle.UnlockMemory(saltData.Length, _auditLogger);
            if (pinnedSaltHandle.IsAllocated)
                pinnedSaltHandle.Free();

            CryptographicOperations.ZeroMemory(derivedKeyData);
            CryptographicOperations.ZeroMemory(saltData);

            throw;
        }
    }
}