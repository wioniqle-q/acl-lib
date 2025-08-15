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

    public IKeyPreparationResult PrepareKey(ReadOnlySpan<byte> password)
    {
        var saltBuffer = CryptoPool.Rent(_keyDerivationService.SaltSize);

        byte[] derivedKeyData = [];
        byte[] saltData = [];
        GCHandle keyHandle = default;
        var isKeyMemoryLocked = 0;

        try
        {
            RandomNumberGenerator.Fill(saltBuffer.AsSpan(0, _keyDerivationService.SaltSize));

            saltData = saltBuffer.AsSpan(0, _keyDerivationService.SaltSize).ToArray();

            derivedKeyData = _keyDerivationService.DeriveKey(
                password,
                saltBuffer.AsSpan(0, _keyDerivationService.SaltSize),
                CryptoConstants.Argon2IdOutputKeyLength);

            keyHandle = GCHandle.Alloc(derivedKeyData, GCHandleType.Pinned);
            if (keyHandle.LockMemory(derivedKeyData.Length, _auditLogger))
                Interlocked.Exchange(ref isKeyMemoryLocked, 1);

            var derivedKeyMemory = new ReadOnlyMemory<byte>(derivedKeyData);
            var saltMemory = new ReadOnlyMemory<byte>(saltData);

            return new KeyPreparationResult(
                derivedKeyMemory,
                saltMemory,
                keyHandle,
                isKeyMemoryLocked,
                _auditLogger);
        }
        catch
        {
            if (Interlocked.CompareExchange(ref isKeyMemoryLocked, 0, 1) is 1)
                keyHandle.UnlockMemory(derivedKeyData.Length, _auditLogger);
            if (keyHandle.IsAllocated)
                keyHandle.Free();

            CryptographicOperations.ZeroMemory(derivedKeyData);
            CryptographicOperations.ZeroMemory(saltData);

            throw;
        }
        finally
        {
            CryptoPool.Return(saltBuffer);
        }
    }

    public IKeyPreparationResult PrepareKeyWithSalt(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt)
    {
        var derivedKeyData = _keyDerivationService.DeriveKey(
            password,
            salt,
            CryptoConstants.Argon2IdOutputKeyLength);

        byte[] saltData = [];
        GCHandle keyHandle = default;
        var isKeyMemoryLocked = 0;

        try
        {
            saltData = salt.ToArray();

            keyHandle = GCHandle.Alloc(derivedKeyData, GCHandleType.Pinned);
            if (keyHandle.LockMemory(derivedKeyData.Length, _auditLogger))
                Interlocked.Exchange(ref isKeyMemoryLocked, 1);

            var derivedKeyMemory = new ReadOnlyMemory<byte>(derivedKeyData);
            var saltMemory = new ReadOnlyMemory<byte>(saltData);

            return new KeyPreparationResult(
                derivedKeyMemory,
                saltMemory,
                keyHandle,
                isKeyMemoryLocked,
                _auditLogger);
        }
        catch
        {
            if (Interlocked.CompareExchange(ref isKeyMemoryLocked, 0, 1) is 1)
                keyHandle.UnlockMemory(derivedKeyData.Length, _auditLogger);
            if (keyHandle.IsAllocated)
                keyHandle.Free();

            CryptographicOperations.ZeroMemory(derivedKeyData);
            CryptographicOperations.ZeroMemory(saltData);

            throw;
        }
    }
}