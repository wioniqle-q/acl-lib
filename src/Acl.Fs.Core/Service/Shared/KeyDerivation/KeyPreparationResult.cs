using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Acl.Fs.Audit.Abstractions;
using Acl.Fs.Core.Abstractions.Service.Shared.KeyDerivation;
using Acl.Fs.Core.Utility;

namespace Acl.Fs.Core.Service.Shared.KeyDerivation;

internal sealed class KeyPreparationResult : IKeyPreparationResult
{
    private readonly IAuditLogger _auditLogger;
    private readonly ReadOnlyMemory<byte> _derivedKey;
    private readonly Lock _lock = new();
    private readonly ReadOnlyMemory<byte> _salt;
    private GCHandle _derivedKeyHandle;
    private int _disposed;
    private int _keyMemoryLocked;

    internal KeyPreparationResult(
        ReadOnlyMemory<byte> derivedKey,
        ReadOnlyMemory<byte> salt,
        GCHandle derivedKeyHandle,
        int keyMemoryLocked,
        IAuditLogger auditLogger)
    {
        _derivedKey = derivedKey;
        _salt = salt;
        _derivedKeyHandle = derivedKeyHandle;
        _keyMemoryLocked = keyMemoryLocked;
        _auditLogger = auditLogger;
    }

    public ReadOnlySpan<byte> DerivedKey
    {
        get
        {
            lock (_lock)
            {
                ThrowIfDisposed();
                return _derivedKey.Span;
            }
        }
    }

    public ReadOnlySpan<byte> Salt
    {
        get
        {
            lock (_lock)
            {
                ThrowIfDisposed();
                return _salt.Span;
            }
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            if (Interlocked.CompareExchange(ref _disposed, 1, 0) is not 0)
                return;

            if (MemoryMarshal.TryGetArray(_derivedKey, out var derivedSegment))
                CryptographicOperations.ZeroMemory(
                    derivedSegment.Array.AsSpan(derivedSegment.Offset, derivedSegment.Count));

            if (MemoryMarshal.TryGetArray(_salt, out var saltSegment))
                CryptographicOperations.ZeroMemory(
                    saltSegment.Array.AsSpan(saltSegment.Offset, saltSegment.Count));

            if (_derivedKeyHandle.IsAllocated)
            {
                if (Interlocked.CompareExchange(ref _keyMemoryLocked, 0, 1) is 1)
                    _derivedKeyHandle.UnlockMemory(_derivedKey.Length, _auditLogger);
                _derivedKeyHandle.Free();
            }
        }
    }

    private void ThrowIfDisposed()
    {
        if (Interlocked.CompareExchange(ref _disposed, 0, 0) is 0) return;
        throw new ObjectDisposedException(nameof(KeyPreparationResult));
    }
}