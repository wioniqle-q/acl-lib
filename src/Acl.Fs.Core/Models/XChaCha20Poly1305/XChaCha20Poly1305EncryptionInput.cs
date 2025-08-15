using System.Security.Cryptography;

namespace Acl.Fs.Core.Models.XChaCha20Poly1305;

public readonly record struct XChaCha20Poly1305EncryptionInput : IDisposable
{
    private readonly byte[] _passwordArray;

    public XChaCha20Poly1305EncryptionInput(ReadOnlyMemory<byte> password)
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