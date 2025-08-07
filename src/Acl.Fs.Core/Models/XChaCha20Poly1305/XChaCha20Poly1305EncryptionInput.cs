namespace Acl.Fs.Core.Models.XChaCha20Poly1305;

public readonly record struct XChaCha20Poly1305EncryptionInput
{
    public XChaCha20Poly1305EncryptionInput(ReadOnlyMemory<byte> password)
    {
        if (password.IsEmpty)
            throw new ArgumentException("Password cannot be empty.", nameof(password));

        Password = password;
    }

    public ReadOnlyMemory<byte> Password { get; }
}