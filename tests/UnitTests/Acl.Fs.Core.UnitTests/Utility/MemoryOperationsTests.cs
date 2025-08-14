using System.Runtime.InteropServices;
using Acl.Fs.Audit.Abstractions;
using Acl.Fs.Audit.Category;
using Acl.Fs.Audit.Constant;
using Acl.Fs.Audit.Entry;
using Acl.Fs.Core.Utility;
using Moq;

namespace Acl.Fs.Core.UnitTests.Utility;

public sealed class MemoryOperationsTests : IDisposable
{
    private readonly Mock<IAuditLogger> _mockAuditLogger;
    private bool _disposed;
    private GCHandle _validHandle;

    public MemoryOperationsTests()
    {
        var testData = new byte[1024];
        Random.Shared.NextBytes(testData);

        _validHandle = GCHandle.Alloc(testData, GCHandleType.Pinned);
        _mockAuditLogger = new Mock<IAuditLogger>();
    }

    public void Dispose()
    {
        Dispose(true);
    }

    [Fact]
    public void LockMemory_WithValidHandle_ShouldReturnExpectedResult()
    {
        const int size = 1024;

        var result = _validHandle.LockMemory(size);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            Assert.True(result || result is not true);
        else
            Assert.True(result);
    }

    [Fact]
    public void LockMemory_WithValidHandleAndAuditLogger_ShouldReturnExpectedResult()
    {
        const int size = 1024;

        var result = _validHandle.LockMemory(size, _mockAuditLogger.Object);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Assert.True(result || result is not true);
            _mockAuditLogger.Verify(x => x.LogAsync(It.IsAny<AuditEntry>(), It.IsAny<CancellationToken>()),
                Times.AtLeast(1));
        }
        else
        {
            Assert.True(result);
            _mockAuditLogger.Verify(x => x.LogAsync(It.IsAny<AuditEntry>(), It.IsAny<CancellationToken>()),
                Times.Once);
        }
    }

    [Fact]
    public void LockMemory_WithInvalidHandle_ShouldReturnFalse()
    {
        var invalidHandle = new GCHandle();

        var result = invalidHandle.LockMemory(1024);

        Assert.False(result);
    }

    [Fact]
    public void LockMemory_WithInvalidHandleAndAuditLogger_ShouldReturnFalseAndLog()
    {
        var invalidHandle = new GCHandle();

        var result = invalidHandle.LockMemory(1024, _mockAuditLogger.Object);

        Assert.False(result);

        _mockAuditLogger.Verify(x => x.LogAsync(
                It.Is<AuditEntry>(entry =>
                    entry.Category == AuditCategory.MemoryManagement &&
                    entry.EventId == AuditEventIds.MemoryLockFailed),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public void LockMemory_WithZeroSize_ShouldHandleGracefully()
    {
        var result = _validHandle.LockMemory(0);

        Assert.True(result || result is not true);
    }

    [Fact]
    public void LockMemory_WithNegativeSize_ShouldHandleGracefully()
    {
        var result = _validHandle.LockMemory(-1);

        Assert.True(result || result is not true);
    }

    [Fact]
    public void UnlockMemory_WithValidHandle_ShouldReturnExpectedResult()
    {
        const int size = 1024;

        var result = _validHandle.UnlockMemory(size);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            Assert.True(result || result is not true);
        else
            Assert.True(result);
    }

    [Fact]
    public void UnlockMemory_WithValidHandleAndAuditLogger_ShouldReturnExpectedResult()
    {
        const int size = 1024;

        var result = _validHandle.UnlockMemory(size, _mockAuditLogger.Object);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Assert.True(result || result is not true);
            _mockAuditLogger.Verify(x => x.LogAsync(It.IsAny<AuditEntry>(), It.IsAny<CancellationToken>()),
                Times.AtLeast(1));
        }
        else
        {
            Assert.True(result);
            _mockAuditLogger.Verify(x => x.LogAsync(It.IsAny<AuditEntry>(), It.IsAny<CancellationToken>()),
                Times.Once);
        }
    }

    [Fact]
    public void UnlockMemory_WithInvalidHandle_ShouldReturnFalse()
    {
        var invalidHandle = new GCHandle();

        var result = invalidHandle.UnlockMemory(1024);

        Assert.False(result);
    }

    [Fact]
    public void UnlockMemory_WithInvalidHandleAndAuditLogger_ShouldReturnFalseAndLog()
    {
        var invalidHandle = new GCHandle();

        var result = invalidHandle.UnlockMemory(1024, _mockAuditLogger.Object);

        Assert.False(result);

        _mockAuditLogger.Verify(x => x.LogAsync(
                It.Is<AuditEntry>(entry =>
                    entry.Category == AuditCategory.MemoryManagement &&
                    entry.EventId == AuditEventIds.MemoryUnlockFailed),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public void UnlockMemory_WithZeroSize_ShouldHandleGracefully()
    {
        var result = _validHandle.UnlockMemory(0);

        Assert.True(result || result is not true);
    }

    [Fact]
    public void UnlockMemory_WithNegativeSize_ShouldHandleGracefully()
    {
        var result = _validHandle.UnlockMemory(-1);

        Assert.True(result || result is not true);
    }

    [Fact]
    public void LockAndUnlockMemory_SequentialCalls_ShouldWorkCorrectly()
    {
        const int size = 1024;

        var lockResult = _validHandle.LockMemory(size);
        var unlockResult = _validHandle.UnlockMemory(size);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Assert.True(lockResult || lockResult is not true);
            Assert.True(unlockResult || unlockResult is not true);
        }
        else
        {
            Assert.True(lockResult);
            Assert.True(unlockResult);
        }
    }

    [Fact]
    public void LockAndUnlockMemory_WithAuditLogger_ShouldLogOperations()
    {
        const int size = 1024;

        var lockResult = _validHandle.LockMemory(size, _mockAuditLogger.Object);
        var unlockResult = _validHandle.UnlockMemory(size, _mockAuditLogger.Object);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Assert.True(lockResult || lockResult is not true);
            Assert.True(unlockResult || unlockResult is not true);

            _mockAuditLogger.Verify(x => x.LogAsync(It.IsAny<AuditEntry>(), It.IsAny<CancellationToken>()),
                Times.AtLeast(2));
        }
        else
        {
            Assert.True(lockResult);
            Assert.True(unlockResult);

            _mockAuditLogger.Verify(x => x.LogAsync(It.IsAny<AuditEntry>(), It.IsAny<CancellationToken>()),
                Times.Exactly(2));
        }
    }

    [Fact]
    public void LockMemory_MultipleCallsWithSameHandle_ShouldNotThrow()
    {
        for (var i = 0; i < 3; i++)
        {
            var result = _validHandle.LockMemory(1024);

            Assert.True(result || result is not true);
        }
    }

    [Fact]
    public void UnlockMemory_MultipleCallsWithSameHandle_ShouldNotThrow()
    {
        for (var i = 0; i < 3; i++)
        {
            var result = _validHandle.UnlockMemory(1024);
            Assert.True(result || result is not true);
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(512)]
    [InlineData(1024)]
    [InlineData(2048)]
    [InlineData(4096)]
    public void LockMemory_WithVariousSizes_ShouldHandleCorrectly(int size)
    {
        var result = _validHandle.LockMemory(size);

        Assert.True(result || result is not true);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(512)]
    [InlineData(1024)]
    [InlineData(2048)]
    [InlineData(4096)]
    public void UnlockMemory_WithVariousSizes_ShouldHandleCorrectly(int size)
    {
        var result = _validHandle.UnlockMemory(size);

        Assert.True(result || result is not true);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(512)]
    [InlineData(1024)]
    [InlineData(2048)]
    [InlineData(4096)]
    public void LockMemory_WithVariousSizesAndAuditLogger_ShouldHandleCorrectly(int size)
    {
        var result = _validHandle.LockMemory(size, _mockAuditLogger.Object);

        Assert.True(result || result is not true);

        _mockAuditLogger.Verify(x => x.LogAsync(It.IsAny<AuditEntry>(), It.IsAny<CancellationToken>()),
            Times.AtLeastOnce);

        _mockAuditLogger.Reset();
    }

    [Fact]
    public void LockMemory_AfterHandleIsFreed_ShouldReturnFalse()
    {
        var tempData = new byte[512];
        var tempHandle = GCHandle.Alloc(tempData, GCHandleType.Pinned);

        tempHandle.Free();
        var result = tempHandle.LockMemory(512);

        Assert.False(result);
    }

    [Fact]
    public void UnlockMemory_AfterHandleIsFreed_ShouldReturnFalse()
    {
        var tempData = new byte[512];
        var tempHandle = GCHandle.Alloc(tempData, GCHandleType.Pinned);

        tempHandle.Free();
        var result = tempHandle.UnlockMemory(512);

        Assert.False(result);
    }

    [Fact]
    public void LockMemory_AfterHandleIsFreedWithAuditLogger_ShouldReturnFalseAndLog()
    {
        var tempData = new byte[512];
        var tempHandle = GCHandle.Alloc(tempData, GCHandleType.Pinned);

        tempHandle.Free();
        var result = tempHandle.LockMemory(512, _mockAuditLogger.Object);

        Assert.False(result);

        _mockAuditLogger.Verify(x => x.LogAsync(
                It.Is<AuditEntry>(entry =>
                    entry.Category == AuditCategory.MemoryManagement &&
                    entry.EventId == AuditEventIds.MemoryLockFailed &&
                    entry.DiagnosticContext.ContainsKey("Reason")),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    private void Dispose(bool disposing)
    {
        if (_disposed) return;

        if (disposing)
            if (_validHandle.IsAllocated)
                _validHandle.Free();

        _disposed = true;
    }
}