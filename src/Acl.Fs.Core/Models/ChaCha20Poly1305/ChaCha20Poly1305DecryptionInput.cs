namespace Acl.Fs.Core.Models.ChaCha20Poly1305;

public readonly record struct ChaCha20Poly1305DecryptionInput
{
    public ChaCha20Poly1305DecryptionInput(ReadOnlyMemory<byte> password)
    {
        if (password.IsEmpty)
            throw new ArgumentException("Password cannot be empty.", nameof(password));

        Password = password;
    }

    public ReadOnlyMemory<byte> Password { get; }
}