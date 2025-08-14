using System.Buffers;
using Acl.Fs.Core.Pool;

namespace Acl.Fs.Core.UnitTests.Pool;

public sealed class CryptoPoolTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(100)]
    [InlineData(1024)]
    [InlineData(4096)]
    public void Rent_WithValidLength_ReturnsArrayOfCorrectSize(int minimumLength)
    {
        var array = CryptoPool.Rent(minimumLength);

        Assert.NotNull(array);
        Assert.True(array.Length >= minimumLength);

        CryptoPool.Return(array);
    }

    [Fact]
    public void Rent_WithNegativeLength_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoPool.Rent(-1));
    }

    [Fact]
    public void Return_WithClearArrayTrue_ClearsMemory()
    {
        var array = CryptoPool.Rent(10);

        for (var i = 0; i < array.Length; i++) array[i] = (byte)(i % 256);

        CryptoPool.Return(array);

        Assert.All(array, b => Assert.Equal(0, b));
    }

    [Fact]
    public void Return_WithClearArrayFalse_DoesNotClearMemory()
    {
        var array = CryptoPool.Rent(10);

        var testData = new byte[] { 1, 2, 3, 4, 5 };
        testData.AsSpan().CopyTo(array);

        var originalData = new byte[array.Length];
        array.AsSpan().CopyTo(originalData);

        CryptoPool.Return(array, false);

        Assert.Equal(originalData, array);
    }

    [Fact]
    public void Return_WithDefaultParameters_ClearsMemory()
    {
        var array = CryptoPool.Rent(10);

        for (var i = 0; i < array.Length; i++) array[i] = (byte)(i % 256);

        CryptoPool.Return(array);

        Assert.All(array, b => Assert.Equal(0, b));
    }


    [Fact]
    public void Return_WithClearLengthGreaterThanArrayLength_ThrowsException()
    {
        var array = CryptoPool.Rent(10);

        Assert.ThrowsAny<ArgumentOutOfRangeException>(() => CryptoPool.Return(array, array.Length + 5));
    }

    [Fact]
    public void Return_WithNegativeClearLength_DoesNotClearMemory()
    {
        var array = CryptoPool.Rent(10);

        var testData = new byte[] { 1, 2, 3, 4, 5 };
        testData.AsSpan().CopyTo(array);

        var originalData = new byte[array.Length];
        array.AsSpan().CopyTo(originalData);

        CryptoPool.Return(array, -1);

        Assert.Equal(originalData, array);
    }

    [Fact]
    public void Return_WithNullArray_ThrowsException()
    {
        Assert.ThrowsAny<Exception>(() => CryptoPool.Return(null!));
        Assert.ThrowsAny<Exception>(() => CryptoPool.Return(null!, 5));
    }

    [Fact]
    public void Shared_ReturnsArrayPoolInstance()
    {
        var sharedPool = CryptoPool.Shared;

        Assert.NotNull(sharedPool);
        Assert.IsType<ArrayPool<byte>>(sharedPool, false);
        Assert.Same(ArrayPool<byte>.Shared, sharedPool);
    }

    [Fact]
    public void RentAndReturn_MultipleOperations_WorksCorrectly()
    {
        var arrays = new byte[5][];

        for (var i = 0; i < arrays.Length; i++)
        {
            arrays[i] = CryptoPool.Rent(100);
            Assert.NotNull(arrays[i]);
            Assert.True(arrays[i].Length >= 100);
        }

        foreach (var t in arrays) CryptoPool.Return(t);

        Assert.True(true);
    }
}