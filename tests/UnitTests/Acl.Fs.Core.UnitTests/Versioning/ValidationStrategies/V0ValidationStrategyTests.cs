using Acl.Fs.Core.Resource;
using Acl.Fs.Core.Versioning.Exceptions;
using Acl.Fs.Core.Versioning.ValidationStrategies;
using static Acl.Fs.Constant.Versioning.VersionConstants;

namespace Acl.Fs.Core.UnitTests.Versioning.ValidationStrategies;

public sealed class V0ValidationStrategyTests
{
    private readonly V0ValidationStrategy _strategy = new();

    [Fact]
    public void Validate_WhenCurrentSupportedMinorVersions_ShouldNotThrow()
    {
        for (byte minorVersion = 1; minorVersion <= CurrentMinorVersion; minorVersion++)
        {
            var currentMinorVersion = minorVersion;
            var exception = Record.Exception(() => _strategy.Validate(currentMinorVersion));
            Assert.Null(exception);
        }
    }

    [Fact]
    public void Validate_WhenMinorVersionIsZero_ShouldNotThrow()
    {
        var exception = Record.Exception(() => _strategy.Validate(0));
        Assert.Null(exception);
    }

    [Fact]
    public void Validate_WhenFutureMinorVersions_ShouldThrowVersionValidationException()
    {
        var futureVersions = new byte[]
        {
            CurrentMinorVersion + 1,
            CurrentMinorVersion + 2,
            CurrentMinorVersion + 10,
            255
        };

        foreach (var minorVersion in futureVersions)
        {
            var exception = Assert.Throws<VersionValidationException>(() =>
                _strategy.Validate(minorVersion));

            var expectedMessage = string.Format(ErrorMessages.FutureMinorVersionNotSupported,
                0, minorVersion, CurrentMinorVersion);
            Assert.Equal(expectedMessage, exception.Message);
        }
    }

    [Fact]
    public void Validate_WhenMinorVersionEqualsCurrentMinorVersion_ShouldNotThrow()
    {
        var exception = Record.Exception(() => _strategy.Validate(CurrentMinorVersion));
        Assert.Null(exception);
    }

    [Fact]
    public void Validate_BoundaryConditions_ShouldWorkCorrectly()
    {
        // Current minor version should be valid
        var exception = Record.Exception(() => _strategy.Validate(CurrentMinorVersion));
        Assert.Null(exception);

        // Previous minor version should be valid (if > 0)
        if (CurrentMinorVersion >= 1)
        {
            var previousException = Record.Exception(() => _strategy.Validate(CurrentMinorVersion - 1));
            Assert.Null(previousException);
        }

        var futureException = Assert.Throws<VersionValidationException>(() =>
            _strategy.Validate(CurrentMinorVersion + 1));
        Assert.NotNull(futureException);
    }

    [Fact]
    public void Validate_WhenFutureMinorVersion_ShouldThrowWithCorrectErrorMessage()
    {
        const byte futureMinorVersion = CurrentMinorVersion + 1;

        var exception = Assert.Throws<VersionValidationException>(() =>
            _strategy.Validate(futureMinorVersion));

        Assert.Contains("0", exception.Message); // Major version
        Assert.Contains(futureMinorVersion.ToString(), exception.Message); // Future minor version
        Assert.Contains(CurrentMinorVersion.ToString(), exception.Message); // Current minor version

        var expectedMessage = string.Format(ErrorMessages.FutureMinorVersionNotSupported,
            0, futureMinorVersion, CurrentMinorVersion);
        Assert.Equal(expectedMessage, exception.Message);
    }

    [Fact]
    public void Validate_ExceptionType_ShouldBeVersionValidationException()
    {
        const byte futureMinorVersion = CurrentMinorVersion + 1;

        var exception = Assert.Throws<VersionValidationException>(() =>
            _strategy.Validate(futureMinorVersion));

        Assert.IsType<VersionValidationException>(exception);
    }

    [Fact]
    public void Validate_WhenValidMinorVersions_ShouldCompleteSuccessfully()
    {
        for (byte minorVersion = 0; minorVersion <= CurrentMinorVersion; minorVersion++)
        {
            var currentMinorVersion = minorVersion;
            var exception = Record.Exception(() => _strategy.Validate(currentMinorVersion));
            Assert.Null(exception);
        }
    }

    [Fact]
    public void Validate_VersionProgression_ShouldBeConsistent()
    {
        Assert.True(CurrentMinorVersion >= 1, "CurrentMinorVersion should be at least 1");

        for (byte version = 1; version <= CurrentMinorVersion; version++)
        {
            var currentVersion = version;
            var exception = Record.Exception(() => _strategy.Validate(currentVersion));
            Assert.Null(exception);
        }

        var futureException = Assert.Throws<VersionValidationException>(() =>
            _strategy.Validate(CurrentMinorVersion + 1));
        Assert.NotNull(futureException);
    }
}