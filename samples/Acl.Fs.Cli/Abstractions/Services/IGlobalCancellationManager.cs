namespace Acl.Fs.Cli.Abstractions.Services;

internal interface IGlobalCancellationManager : IDisposable
{
    CancellationToken Token { get; }
    void CancelAll(string reason, Exception? exception = null);
    CancellationToken CombineWith(CancellationToken cancellationToken);

    Task ExecuteWithCancellationOnCryptoErrorAsync(Func<CancellationToken, Task> operation,
        CancellationToken cancellationToken = default);
}