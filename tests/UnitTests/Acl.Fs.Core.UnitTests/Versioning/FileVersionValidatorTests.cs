using Acl.Fs.Core.Resource;
using Acl.Fs.Core.Versioning;
using Acl.Fs.Core.Versioning.Exceptions;
using Microsoft.Extensions.Logging;
using Moq;
using static Acl.Fs.Constant.Versioning.VersionConstants;

namespace Acl.Fs.Core.UnitTests.Versioning;

public sealed class FileVersionValidatorTests
{
    private readonly FileVersionValidator _validator;

    public FileVersionValidatorTests()
    {
        var mockLogger = new Mock<ILogger<FileVersionValidator>>();
        _validator = new FileVersionValidator(mockLogger.Object);
    }

    [Fact]
    public void Constructor_WhenLoggerIsNull_ShouldThrowArgumentNullException()
    {
        var exception = Assert.Throws<ArgumentNullException>(() => new FileVersionValidator(null!));
        Assert.Equal("logger", exception.ParamName);
    }

    [Theory]
    [InlineData(0, 1)] // Current beta version
    public void ValidateVersion_WhenCurrentSupportedVersion_ShouldNotThrow(byte majorVersion, byte minorVersion)
    {
        var exception = Record.Exception(() => _validator.ValidateVersion(majorVersion, minorVersion));
        Assert.Null(exception);
    }

    [Fact]
    public void ValidateVersion_WhenVersionIsZeroZero_ShouldThrowVersionValidationException()
    {
        var exception = Assert.Throws<VersionValidationException>(() =>
            _validator.ValidateVersion(0, 0));

        Assert.Equal(ErrorMessages.InvalidVersionZeroZero, exception.Message);
    }

    [Theory]
    [InlineData(1, 0)] // Future major version
    [InlineData(2, 0)]
    [InlineData(255, 0)]
    public void ValidateVersion_WhenFutureMajorVersion_ShouldThrowVersionValidationException(byte majorVersion,
        byte minorVersion)
    {
        var exception = Assert.Throws<VersionValidationException>(() =>
            _validator.ValidateVersion(majorVersion, minorVersion));

        var expectedMessage = string.Format(ErrorMessages.FutureMajorVersionNotSupported,
            majorVersion, minorVersion, CurrentMajorVersion);
        Assert.Equal(expectedMessage, exception.Message);
    }

    [Theory]
    [InlineData(0, 2)] // Future minor version for current major version
    [InlineData(0, 3)]
    [InlineData(0, 255)]
    public void ValidateVersion_WhenFutureMinorVersionForCurrentMajor_ShouldThrowVersionValidationException(
        byte majorVersion, byte minorVersion)
    {
        var exception = Assert.Throws<VersionValidationException>(() =>
            _validator.ValidateVersion(majorVersion, minorVersion));

        var expectedMessage = string.Format(ErrorMessages.FutureMinorVersionNotSupported,
            majorVersion, minorVersion, CurrentMinorVersion);
        Assert.Equal(expectedMessage, exception.Message);
    }

    [Theory]
    [InlineData(1, 0)] // Future major version with minor 0
    [InlineData(1, 5)] // Future major version with any minor
    [InlineData(2, 10)]
    public void ValidateVersion_WhenFutureMajorVersionWithAnyMinor_ShouldThrowVersionValidationException(
        byte majorVersion, byte minorVersion)
    {
        var exception = Assert.Throws<VersionValidationException>(() =>
            _validator.ValidateVersion(majorVersion, minorVersion));

        var expectedMessage = string.Format(ErrorMessages.FutureMajorVersionNotSupported,
            majorVersion, minorVersion, CurrentMajorVersion);
        Assert.Equal(expectedMessage, exception.Message);
    }

    [Theory]
    [InlineData(0, 1)] // Valid cases
    public void ValidateVersion_WhenValidVersion_ShouldCompleteSuccessfully(byte majorVersion, byte minorVersion)
    {
        var exception = Record.Exception(() => _validator.ValidateVersion(majorVersion, minorVersion));
        Assert.Null(exception);
    }

    [Theory]
    [InlineData(0, 0)] // Invalid v0.0
    [InlineData(0, 2)] // Future minor for v0.x
    [InlineData(1, 0)] // Future major
    [InlineData(255, 255)] // Way future version
    public void ValidateVersion_WhenInvalidVersions_ShouldThrowVersionValidationException(byte majorVersion,
        byte minorVersion)
    {
        var exception = Assert.Throws<VersionValidationException>(() =>
            _validator.ValidateVersion(majorVersion, minorVersion));

        Assert.NotNull(exception);
        Assert.IsType<VersionValidationException>(exception);
    }
}