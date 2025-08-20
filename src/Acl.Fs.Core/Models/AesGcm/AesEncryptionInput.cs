using System.Security.Cryptography;

namespace Acl.Fs.Core.Models.AesGcm;

public readonly record struct AesEncryptionInput : IDisposable
{
    private readonly byte[] _passwordArray;

    public AesEncryptionInput(ReadOnlyMemory<byte> password)
    {
        if (password.IsEmpty)
            throw new ArgumentException("Password cannot be empty.", nameof(password));

        _passwordArray = password.ToArray();
    }

    public ReadOnlyMemory<byte> Password => _passwordArray.AsMemory();

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_passwordArray);
    }
}