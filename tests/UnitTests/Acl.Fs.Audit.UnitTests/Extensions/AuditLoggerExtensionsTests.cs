using System.Collections.Frozen;
using Acl.Fs.Audit.Abstractions;
using Acl.Fs.Audit.Extensions;
using Moq;

namespace Acl.Fs.Audit.UnitTests.Extensions;

public sealed class AuditLoggerExtensionsTests
{
    [Fact]
    public async Task AuditAsync_ShouldCallLogAsyncWithCorrectAuditEntry()
    {
        const string category = "UnitTest";
        const string message = "Something tested";
        const int eventId = 99;

        var loggerMock = new Mock<IAuditLogger>();
        var logger = loggerMock.Object;
        var diagnosticContext = new Dictionary<string, object?> { { "x", 1 } }.ToFrozenDictionary();
        var ct = new CancellationTokenSource().Token;

        await logger.AuditAsync(category, message, eventId, diagnosticContext, ct);

        loggerMock.Verify(l => l.LogAsync(
            It.Is<IAuditEntry>(e =>
                e.Category == category &&
                e.Message == message &&
                e.EventId == eventId &&
                e.DiagnosticContext.ContainsKey("x")
            ),
            ct), Times.Once);
    }
}