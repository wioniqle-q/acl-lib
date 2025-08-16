using System.Buffers.Binary;
using System.Security.Cryptography;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.Utility;

internal static class CryptoOperations
{
    internal static void PrecomputeSalt(ReadOnlySpan<byte> originalNonce, Span<byte> salt)
    {
        Span<byte> input = stackalloc byte[8];

        try
        {
            BinaryPrimitives.WriteInt64LittleEndian(input, 0L);

            if (IsRunningOnGitHubActions)
            {
                using var hmac = new HMACSHA256(originalNonce.ToArray());
                if (hmac.TryComputeHash(input, salt, out var bytesWritten) is not true ||
                    bytesWritten != SaltSize)
                    throw new CryptographicException("Failed to derive salt for cryptographic operation.");
            }
            else
            {
                using var hmac = new HMACSHA3_512(originalNonce.ToArray());
                if (hmac.TryComputeHash(input, salt, out var bytesWritten) is not true ||
                    bytesWritten != SaltSize)
                    throw new CryptographicException("Failed to derive salt for cryptographic operation.");
            }
        }
        catch (Exception ex) when (ex is not CryptographicException)
        {
            throw new CryptographicException("Failed to derive salt for cryptographic operation.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    internal static void DeriveNonce(byte[] salt, long blockIndex, byte[] outputNonce,
        int nonceSize = NonceSize)
    {
        if (IsRunningOnGitHubActions)
        {
            Span<byte> blockIndexBytes = stackalloc byte[sizeof(long)];
            Span<byte> prk = stackalloc byte[HmacKeySize];
            Span<byte> info = stackalloc byte[sizeof(long) + NonceContext.Length];
            Span<byte> okm = stackalloc byte[nonceSize];

            try
            {
                BinaryPrimitives.WriteInt64LittleEndian(blockIndexBytes, blockIndex);

                using (var hmac = new HMACSHA256(salt))
                {
                    if (hmac.TryComputeHash(blockIndexBytes, prk, out var bytesWritten) is not true ||
                        bytesWritten != HmacKeySize)
                        throw new CryptographicException("HMAC computation failed for cryptographic operation.");
                }

                blockIndexBytes.CopyTo(info);
                NonceContext.CopyTo(info[sizeof(long)..]);

                HKDF.Expand(HashAlgorithmName.SHA256, prk, okm, info);

                okm.CopyTo(outputNonce.AsSpan(0, nonceSize));
            }
            catch (Exception ex) when (ex is not CryptographicException)
            {
                throw new CryptographicException("Failed to derive nonce for cryptographic operation.", ex);
            }
            finally
            {
                prk.Clear();
                okm.Clear();
                info.Clear();
                blockIndexBytes.Clear();
            }
        }
        else
        {
            Span<byte> input = stackalloc byte[salt.Length + sizeof(long)];

            try
            {
                salt.CopyTo(input);
                BinaryPrimitives.WriteInt64LittleEndian(input[salt.Length..], blockIndex);

                using var shake256 = new Shake256();
                shake256.AppendData(input);
                shake256.GetHashAndReset(outputNonce.AsSpan(0, nonceSize));
            }
            catch (Exception ex)
            {
                throw new CryptographicException("Failed to derive nonce for cryptographic operation.", ex);
            }
            finally
            {
                input.Clear();
            }
        }
    }

    internal static void ValidateHeaderSalt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> headerSalt)
    {
        Span<byte> computedSalt = stackalloc byte[SaltSize];

        try
        {
            PrecomputeSalt(nonce, computedSalt);

            if (CryptographicOperations.FixedTimeEquals(computedSalt, headerSalt) is not true)
                throw new CryptographicException(
                    "Header salt does not match computed salt. Possible tampering or corruption detected.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(computedSalt);
        }
    }
}