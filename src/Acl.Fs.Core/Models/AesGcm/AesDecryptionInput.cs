namespace Acl.Fs.Core.Models.AesGcm;

public readonly record struct AesDecryptionInput
{
    public AesDecryptionInput(ReadOnlyMemory<byte> password)
    {
        if (password.IsEmpty)
            throw new ArgumentException("Password cannot be empty.", nameof(password));

        Password = password;
    }

    public ReadOnlyMemory<byte> Password { get; }
}