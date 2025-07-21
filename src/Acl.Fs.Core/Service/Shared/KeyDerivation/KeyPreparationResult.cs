using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Acl.Fs.Constant.Cryptography;
using Acl.Fs.Core.Abstractions.Service.Shared.KeyDerivation;
using Acl.Fs.Core.Pool;

namespace Acl.Fs.Core.Service.Shared.KeyDerivation;

internal sealed class KeyPreparationResult : IKeyPreparationResult
{
    private readonly ReadOnlyMemory<byte> _derivedKey;
    private readonly Lock _lock = new();
    private readonly ReadOnlyMemory<byte> _salt;
    private int _disposed;

    public KeyPreparationResult(IKeyDerivationService keyDerivationService, ReadOnlySpan<byte> sourceKey)
    {
        var saltBuffer = CryptoPool.Rent(keyDerivationService.SaltSize);

        try
        {
            RandomNumberGenerator.Fill(saltBuffer.AsSpan(0, keyDerivationService.SaltSize));
            var derivedKey =
                keyDerivationService.DeriveKey(sourceKey, saltBuffer.AsSpan(0, keyDerivationService.SaltSize),
                    CryptoConstants.Argon2IdOutputKeyLength);

            _derivedKey = new ReadOnlyMemory<byte>(derivedKey.ToArray());
            _salt = new ReadOnlyMemory<byte>(saltBuffer.AsSpan(0, keyDerivationService.SaltSize).ToArray());
        }
        finally
        {
            CryptoPool.Return(saltBuffer);
        }
    }

    public KeyPreparationResult(IKeyDerivationService keyDerivationService, ReadOnlySpan<byte> sourceKey,
        ReadOnlySpan<byte> salt)
    {
        var derivedKey = keyDerivationService.DeriveKey(sourceKey, salt, CryptoConstants.Argon2IdOutputKeyLength);

        _derivedKey = new ReadOnlyMemory<byte>(derivedKey.ToArray());
        _salt = new ReadOnlyMemory<byte>(salt.ToArray());
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
            if (_disposed is not 0)
                return;

            _disposed = 1;

            if (MemoryMarshal.TryGetArray(_derivedKey, out var derivedSegment))
                CryptographicOperations.ZeroMemory(
                    derivedSegment.Array.AsSpan(derivedSegment.Offset, derivedSegment.Count));

            if (MemoryMarshal.TryGetArray(_salt, out var saltSegment))
                CryptographicOperations.ZeroMemory(
                    saltSegment.Array.AsSpan(saltSegment.Offset, saltSegment.Count));
        }
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) is 0) return;
        throw new ObjectDisposedException(nameof(KeyPreparationResult));
    }
}