namespace Acl.Fs.Cli.Configuration;

internal sealed class CryptoSettings
{
    public string DefaultEncryptedPrefix { get; init; } = null!;
    public int MaxConcurrency { get; init; }
    public bool OverwriteExisting { get; init; }
}