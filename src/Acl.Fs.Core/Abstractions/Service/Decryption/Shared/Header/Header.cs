namespace Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Header;

internal readonly record struct Header(
    byte MajorVersion,
    byte MinorVersion,
    long OriginalSize,
    byte[] Nonce,
    byte[] ChaCha20Salt,
    byte[] Argon2Salt
);