namespace Acl.Fs.Constant.Cryptography;

internal static class CryptoConstants
{
    internal const int NonceSize = 12;
    internal const int XChaCha20Poly1305NonceSize = 24;
    internal const int TagSize = 16;
    internal const int Argon2IdSaltSize = 16;
    internal const int Argon2IdDegreeOfParallelism = 1;
    internal const int Argon2IdMemorySize = 65536;
    internal const int Argon2IdNumberOfPasses = 6;
    internal const int Argon2IdOutputKeyLength = 32;

    internal static readonly byte[] NonceContext =
        [0x41, 0x43, 0x4C, 0x5F, 0x4E, 0x4F, 0x4E, 0x43, 0x45];

    internal static int HmacKeySize => 32;
    internal static int SaltSize => IsRunningOnGitHubActions ? 32 : 64;

    internal static bool IsRunningOnGitHubActions =>
        Environment.GetEnvironmentVariable("GITHUB_ACTIONS") is "true" ||
        Environment.GetEnvironmentVariable("CI") is "true";
}