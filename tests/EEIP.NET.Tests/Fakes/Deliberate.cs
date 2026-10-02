namespace EEIP.NET.Tests.Fakes;

/// <summary>
/// Malformed input from the network has to be rejected on purpose. This tells a deliberate rejection (a
/// <c>CIPException</c>, <c>IOException</c>, <c>InvalidDataException</c>, ...) from an accident of the parser
/// (index out of range, negative array size, null dereference, ...) without pinning the exact exception type.
/// </summary>
public static class Deliberate
{
    private static readonly Type[] AccidentalTypes =
    [
        typeof(IndexOutOfRangeException),
        typeof(OverflowException),
        typeof(NullReferenceException),
        typeof(ArgumentException), // also covers ArgumentNull/ArgumentOutOfRange (Array.Copy, Encoding.GetString, ...)
        typeof(InvalidCastException),
        typeof(DivideByZeroException),
        typeof(ArrayTypeMismatchException),
    ];

    public static bool IsAccident(Exception exception) =>
        AccidentalTypes.Any(type => type.IsInstanceOfType(exception));

    public static void AssertThrows(Action action, string because)
    {
        var exception = Record.Exception(action);
        Assert.True(exception is not null, $"Expected a deliberate exception ({because}), but nothing was thrown.");
        Assert.False(IsAccident(exception), $"Expected a deliberate exception ({because}), but got an accident: {exception}");
    }

    /// <summary>Passes when the parser either returns <c>null</c> or throws something deliberate.</summary>
    public static void AssertRejects<T>(Func<T?> parse, string because) where T : class
    {
        T? result = null;
        var exception = Record.Exception(() => result = parse());
        if (exception is not null)
            Assert.False(IsAccident(exception), $"Expected a clean rejection ({because}), but got an accident: {exception}");
        else
            Assert.True(result is null, $"Expected a clean rejection ({because}), but the input was accepted.");
    }
}
