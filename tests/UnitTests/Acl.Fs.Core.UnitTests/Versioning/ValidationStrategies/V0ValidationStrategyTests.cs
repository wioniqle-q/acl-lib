using Acl.Fs.Core.Resource;
using Acl.Fs.Core.Versioning.Exceptions;
using Acl.Fs.Core.Versioning.ValidationStrategies;
using static Acl.Fs.Constant.Versioning.VersionConstants;

namespace Acl.Fs.Core.UnitTests.Versioning.ValidationStrategies;

public sealed class V0ValidationStrategyTests
{
    private readonly V0ValidationStrategy _strategy = new();

    [Theory]
    [InlineData(1)] // Current supported minor version
    public void Validate_WhenCurrentSupportedMinorVersion_ShouldNotThrow(byte minorVersion)
    {
        var exception = Record.Exception(() => _strategy.Validate(minorVersion));
        Assert.Null(exception);
    }

    [Theory]
    [InlineData(0)] // Minor version 0 is not supported for v0.x
    public void Validate_WhenMinorVersionIsZero_ShouldNotThrow(byte minorVersion)
    {
        var exception = Record.Exception(() => _strategy.Validate(minorVersion));
        Assert.Null(exception);
    }

    [Theory]
    [InlineData(2)] // Future minor version
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(10)]
    [InlineData(255)] // Maximum byte value
    public void Validate_WhenFutureMinorVersion_ShouldThrowVersionValidationException(byte minorVersion)
    {
        var exception = Assert.Throws<VersionValidationException>(() =>
            _strategy.Validate(minorVersion));

        var expectedMessage = string.Format(ErrorMessages.FutureMinorVersionNotSupported,
            0, minorVersion, CurrentMinorVersion);
        Assert.Equal(expectedMessage, exception.Message);
    }

    [Fact]
    public void Validate_WhenMinorVersionEqualsCurrentMinorVersion_ShouldNotThrow()
    {
        var exception = Record.Exception(() => _strategy.Validate(CurrentMinorVersion));
        Assert.Null(exception);
    }

    [Fact]
    public void Validate_WhenMinorVersionIsOneLessThanCurrent_ShouldNotThrow()
    {
        // Test boundary condition: current minor version - 1
        const byte minorVersion = CurrentMinorVersion - 1;

        var exception = Record.Exception(() => _strategy.Validate(minorVersion));
        Assert.Null(exception);
    }

    [Fact]
    public void Validate_WhenMinorVersionIsOneMoreThanCurrent_ShouldThrowVersionValidationException()
    {
        // Test boundary condition: current minor version + 1
        const byte minorVersion = CurrentMinorVersion + 1;

        var exception = Assert.Throws<VersionValidationException>(() =>
            _strategy.Validate(minorVersion));

        var expectedMessage = string.Format(ErrorMessages.FutureMinorVersionNotSupported,
            0, minorVersion, CurrentMinorVersion);
        Assert.Equal(expectedMessage, exception.Message);
    }

    [Theory]
    [InlineData(2, "0", "2", "1")] // v0.2 when current is v0.1
    [InlineData(5, "0", "5", "1")] // v0.5 when current is v0.1
    [InlineData(255, "0", "255", "1")] // v0.255 when current is v0.1
    public void Validate_WhenFutureMinorVersion_ShouldThrowWithCorrectErrorMessage(
        byte minorVersion, string expectedMajor, string expectedMinor, string expectedCurrent)
    {
        var exception = Assert.Throws<VersionValidationException>(() =>
            _strategy.Validate(minorVersion));

        Assert.Contains(expectedMajor, exception.Message);
        Assert.Contains(expectedMinor, exception.Message);
        Assert.Contains(expectedCurrent, exception.Message);

        var expectedMessage = string.Format(ErrorMessages.FutureMinorVersionNotSupported,
            0, minorVersion, CurrentMinorVersion);
        Assert.Equal(expectedMessage, exception.Message);
    }

    [Fact]
    public void Validate_ExceptionType_ShouldBeVersionValidationException()
    {
        var exception = Assert.Throws<VersionValidationException>(() =>
            _strategy.Validate(2));

        Assert.IsType<VersionValidationException>(exception);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void Validate_WhenValidMinorVersions_ShouldCompleteSuccessfully(byte minorVersion)
    {
        // Only test versions that are <= CurrentMinorVersion
        if (minorVersion > CurrentMinorVersion) return;

        var exception = Record.Exception(() => _strategy.Validate(minorVersion));
        Assert.Null(exception);
    }
}