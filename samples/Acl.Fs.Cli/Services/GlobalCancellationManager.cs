using System.Security.Cryptography;
using Acl.Fs.Cli.Abstractions.Services;
using Microsoft.Extensions.Logging;

namespace Acl.Fs.Cli.Services;

internal sealed class GlobalCancellationManager(ILogger<GlobalCancellationManager> logger) : IGlobalCancellationManager
{
    private readonly CancellationTokenSource _globalCancellationSource = new();

    private readonly ILogger<GlobalCancellationManager> _logger =
        logger ?? throw new ArgumentNullException(nameof(logger));

    private Exception? _cancellationException;
    private string? _cancellationReason;

    private volatile bool _isCancelled;

    public CancellationToken Token => _globalCancellationSource.Token;

    public void CancelAll(string reason, Exception? exception = null)
    {
        if (_isCancelled)
        {
            _logger.LogDebug("Global cancellation already triggered. Reason: {Reason}", _cancellationReason);
            return;
        }

        _isCancelled = true;
        _cancellationReason = reason;
        _cancellationException = exception;

        _logger.LogError(exception, "Global cancellation triggered: {Reason}", reason);

        try
        {
            _globalCancellationSource.Cancel();
        }
        catch (ObjectDisposedException)
        {
            _logger.LogDebug("Global cancellation token source was already disposed");
        }
    }

    public CancellationToken CombineWith(CancellationToken cancellationToken)
    {
        return cancellationToken == CancellationToken.None
            ? Token
            : CancellationTokenSource.CreateLinkedTokenSource(Token, cancellationToken).Token;
    }

    public async Task ExecuteWithCancellationOnCryptoErrorAsync(Func<CancellationToken, Task> operation,
        CancellationToken cancellationToken = default)
    {
        var combinedToken = CombineWith(cancellationToken);

        try
        {
            await operation(combinedToken);
        }
        catch (AuthenticationTagMismatchException ex)
        {
            CancelAll("Authentication tag mismatch - invalid key or corrupted data", ex);
            throw;
        }
        catch (CryptographicException ex)
        {
            CancelAll("Cryptographic error occurred", ex);
            throw;
        }
        catch (OperationCanceledException) when (Token.IsCancellationRequested &&
                                                 !cancellationToken.IsCancellationRequested)
        {
            var message = _cancellationException is not null
                ? $"Operation cancelled due to: {_cancellationReason}. Original error: {_cancellationException.Message}"
                : $"Operation cancelled due to: {_cancellationReason}";

            throw new OperationCanceledException(message, _cancellationException);
        }
    }

    public void Dispose()
    {
        _globalCancellationSource.Dispose();
    }
}