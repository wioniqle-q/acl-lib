using System.Runtime.CompilerServices;
using Acl.Fs.Stream.Abstractions.Implementation.PlatformConfiguration;
using Acl.Fs.Stream.Core;
using Microsoft.Extensions.Logging;

namespace Acl.Fs.Stream.Abstractions;

internal abstract class DirectStreamBase<TStream> : System.IO.Stream where TStream : System.IO.Stream
{
    private readonly IPlatformConfiguration _platformConfiguration;
    internal readonly TStream InnerStream;
    private volatile bool _disposed;

    protected DirectStreamBase(TStream innerStream, ILogger? logger = null)
    {
        InnerStream = innerStream ?? throw new ArgumentNullException(nameof(innerStream));
        _platformConfiguration = PlatformConfigurationFactory.Create(logger);

        ConfigurePlatformProperties();
    }

    public override bool CanRead => InnerStream.CanRead;
    public override bool CanSeek => InnerStream.CanSeek;
    public override bool CanWrite => InnerStream.CanWrite;
    public override long Length => InnerStream.Length;

    public override long Position
    {
        get => InnerStream.Position;
        set => InnerStream.Position = value;
    }

    public override async Task FlushAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();

        await InnerStream.FlushAsync(cancellationToken);
        ExecutePlatformSpecificFlush(cancellationToken);
    }

    public override void Flush()
    {
        InnerStream.Flush();
        ExecutePlatformSpecificFlush(CancellationToken.None);
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        ThrowIfDisposed();
        return InnerStream.Read(buffer.AsSpan(offset, count));
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();

        return await InnerStream.ReadAsync(buffer.AsMemory(offset, count), cancellationToken);
    }

    [AsyncMethodBuilder(typeof(PoolingAsyncValueTaskMethodBuilder<>))]
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();

        return await InnerStream.ReadAsync(buffer, cancellationToken);
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        ThrowIfDisposed();
        return InnerStream.Seek(offset, origin);
    }

    public override void SetLength(long value)
    {
        ThrowIfDisposed();
        InnerStream.SetLength(value);
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        ThrowIfDisposed();
        InnerStream.Write(buffer.AsSpan(offset, count));
    }

    public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();

        await InnerStream.WriteAsync(buffer.AsMemory(offset, count), cancellationToken);
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();

        await InnerStream.WriteAsync(buffer, cancellationToken);
    }

    protected override void Dispose(bool disposing)
    {
        if (_disposed) return;
        _disposed = true;

        if (disposing)
            InnerStream.Dispose();

        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;

        if (InnerStream is IAsyncDisposable asyncDisposable)
            await asyncDisposable.DisposeAsync();
        else
            InnerStream.Dispose();

        GC.SuppressFinalize(this);
    }

    private void ConfigurePlatformProperties()
    {
        _platformConfiguration.ConfigureStream(InnerStream);
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    protected abstract void ExecutePlatformSpecificFlush(CancellationToken cancellationToken);
}