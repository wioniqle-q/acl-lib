using System.Buffers.Binary;
using System.Security.Cryptography;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.Utility;

internal static class CryptoOperations
{
    internal static void PrecomputeSalt(byte[] originalNonce, byte[] salt)
    {
        Span<byte> input = stackalloc byte[8];

        try
        {
            BinaryPrimitives.WriteInt64LittleEndian(input, 0L);

            if (IsRunningOnGitHubActions)
            {
                using var hmac = new HMACSHA256(originalNonce);
                if (hmac.TryComputeHash(input, salt, out var bytesWritten) is not true ||
                    bytesWritten != SaltSize)
                    throw new CryptographicException("Failed to derive salt for cryptographic operation.");
            }
            else
            {
                using var hmac = new HMACSHA3_512(originalNonce);
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
            input.Clear();
        }
    }

    internal static void DeriveNonce(byte[] salt, long blockIndex, byte[] outputNonce,
        int nonceSize = NonceSize)
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