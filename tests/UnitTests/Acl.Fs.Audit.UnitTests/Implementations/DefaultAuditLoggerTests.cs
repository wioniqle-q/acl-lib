using System.Collections.Frozen;
using Acl.Fs.Audit.Entry;
using Acl.Fs.Audit.Implementation;
using Microsoft.Extensions.Logging;
using Moq;

namespace Acl.Fs.Audit.UnitTests.Implementations;

public sealed class DefaultAuditLoggerTests
{
    [Fact]
    public async Task LogAsync_Should_CallILoggerWithExpectedParameters()
    {
        var loggerMock = new Mock<ILogger<DefaultAuditLogger>>();
        var auditLogger = new DefaultAuditLogger(loggerMock.Object);
        var now = DateTimeOffset.UtcNow;
        var entry = new AuditEntry(now, "TestCat", "TestMsg", 123,
            new Dictionary<string, object?> { { "k", "v" } }.ToFrozenDictionary());

        await auditLogger.LogAsync(entry);

        loggerMock.Verify(l => l.Log(
            LogLevel.Information,
            It.IsAny<EventId>(),
            It.Is<It.IsAnyType>((v, t) =>
                v.ToString()!.Contains("[AUDIT]") && v.ToString()!.Contains("TestCat") &&
                v.ToString()!.Contains("TestMsg") && v.ToString()!.Contains("123") && v.ToString()!.Contains("k=v")),
            null,
            It.IsAny<Func<It.IsAnyType, Exception?, string>>()
        ), Times.Once);
    }
}