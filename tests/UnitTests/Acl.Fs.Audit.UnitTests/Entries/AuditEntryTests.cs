using System.Collections.Frozen;
using Acl.Fs.Audit.Entry;

namespace Acl.Fs.Audit.UnitTests.Entries;

public sealed class AuditEntryTests
{
    [Fact]
    public void Constructor_ShouldSetPropertiesCorrectly()
    {
        const string category = "File";
        const string message = "Opened file.txt";
        const int eventId = 50;

        var now = DateTimeOffset.UtcNow;

        var context = new Dictionary<string, object?> { { "key", "value" } }.ToFrozenDictionary();

        var entry = new AuditEntry(now, category, message, eventId, context);

        Assert.Equal(now, entry.TimestampUtc);
        Assert.Equal(category, entry.Category);
        Assert.Equal(message, entry.Message);
        Assert.Equal(eventId, entry.EventId);
        Assert.Equal(context, entry.DiagnosticContext);
    }

    [Fact]
    public void Constructor_ShouldSetEmptyDictionary_WhenDiagnosticContextIsNull()
    {
        var now = DateTimeOffset.UtcNow;

        var entry = new AuditEntry(now, "cat", "msg");

        Assert.NotNull(entry.DiagnosticContext);
        Assert.Empty(entry.DiagnosticContext);
    }
}