using EEIP.NET.Tests.Fakes;
using Sres.Net.EEIP;

namespace EEIP.NET.Tests.SuspectedBugs;

/// <summary>
/// Item 7: <c>ReceiveCallbackClass1</c>, the callback for class 1 T-to-O packets, trusts whatever arrives on the
/// originator's UDP port.
/// </summary>
[Trait("Category", "SuspectedBug")]
public sealed class ImplicitReceiveBugTests
{
    private static readonly byte[] Zeros = new byte[4];
    private static readonly byte[] First = [0xA1, 0xA2, 0xA3, 0xA4];
    private static readonly byte[] Second = [0xB1, 0xB2, 0xB3, 0xB4];

    private static byte[] Head(EEIPClient client) => client.T_O_IOData[..4];

    private static void WaitForData(EEIPClient client, byte[] expected) =>
        Assert.True(SpinWait.SpinUntil(() => Head(client).SequenceEqual(expected), ImplicitHarness.Timeout),
            $"T_O_IOData never became {Convert.ToHexString(expected)}, is {Convert.ToHexString(Head(client))}");

    /// <summary>
    /// Sends a packet the client is expected to reject and gives it time to be handled. A rejected packet leaves no
    /// trace to wait for (not even LastReceivedImplicitMessage, which only counts accepted packets), so this waits.
    /// </summary>
    private static async Task SendAndWaitUntilHandled(ImplicitHarness harness, byte[] packet)
    {
        await harness.SendToOriginatorAsync(packet, TestContext.Current.CancellationToken);
        await Task.Delay(300, TestContext.Current.CancellationToken);
    }

    // ---- an oversized or undersized datagram throws on a threadpool thread, which terminates the process ----

    [Fact]
    public Task Item07_OversizedPacket_DoesNotKillTheProcess() =>
        IsolatedScenario.AssertPassesAsync(typeof(ImplicitReceiveBugTests), nameof(Scenario_OversizedPacket), TestContext.Current.CancellationToken);

    [Fact]
    public async Task Scenario_OversizedPacket()
    {
        IsolatedScenario.SkipUnlessRequested(nameof(Scenario_OversizedPacket));
        using var harness = new ImplicitHarness();
        harness.Client.ForwardOpen();
        try
        {
            // 600 bytes of payload do not fit the 505 byte T_O_IOData buffer.
            await harness.SendToOriginatorAsync(ImplicitHarness.BuildTOPacket(ImplicitHarness.ConnectionIdTO, new byte[600], sequence: 1), TestContext.Current.CancellationToken);
            await Task.Delay(500, TestContext.Current.CancellationToken);

            // The connection must still work afterwards.
            await harness.SendToOriginatorAsync(ImplicitHarness.BuildTOPacket(ImplicitHarness.ConnectionIdTO, First, sequence: 2), TestContext.Current.CancellationToken);
            WaitForData(harness.Client, First);
        }
        finally
        {
            harness.TryForwardClose();
        }
    }

    [Fact]
    public Task Item07_PacketShorterThanTheRealTimeHeader_DoesNotKillTheProcess() =>
        IsolatedScenario.AssertPassesAsync(typeof(ImplicitReceiveBugTests), nameof(Scenario_PacketShorterThanRealTimeHeader), TestContext.Current.CancellationToken);

    [Fact]
    public async Task Scenario_PacketShorterThanRealTimeHeader()
    {
        IsolatedScenario.SkipUnlessRequested(nameof(Scenario_PacketShorterThanRealTimeHeader));
        using var harness = new ImplicitHarness(c => c.T_O_RealTimeFormat = RealTimeFormat.Header32Bit);
        harness.Client.ForwardOpen();
        try
        {
            // 22 bytes: 20 byte envelope + 2 bytes where the format promises a 4 byte run/idle header.
            await harness.SendToOriginatorAsync(ImplicitHarness.BuildTOPacket(ImplicitHarness.ConnectionIdTO, [0x01, 0x00], sequence: 1), TestContext.Current.CancellationToken);
            await Task.Delay(500, TestContext.Current.CancellationToken);

            await harness.SendToOriginatorAsync(ImplicitHarness.BuildTOPacket(ImplicitHarness.ConnectionIdTO, [0x01, 0x00, 0x00, 0x00, .. First], sequence: 2), TestContext.Current.CancellationToken);
            WaitForData(harness.Client, First);
        }
        finally
        {
            harness.TryForwardClose();
        }
    }

    // ---- re-opening: udpClientReceiveClosed is one flag per client, not per socket ----

    [Fact]
    public Task Item07_ReopeningTheConnectionRightAfterClosing_DoesNotKillTheProcess() =>
        IsolatedScenario.AssertPassesAsync(typeof(ImplicitReceiveBugTests), nameof(Scenario_ReopenAfterClose), TestContext.Current.CancellationToken);

    [Fact]
    public async Task Scenario_ReopenAfterClose()
    {
        IsolatedScenario.SkipUnlessRequested(nameof(Scenario_ReopenAfterClose));
        using var harness = new ImplicitHarness();
        try
        {
            // ForwardClose sets the flag and closes the socket; the aborted receive of that socket completes later on a
            // threadpool thread, and the next ForwardOpen has meanwhile reset the flag, so the callback re-arms a disposed socket.
            for (int i = 0; i < 30; i++)
            {
                harness.Client.ForwardOpen();
                harness.Client.ForwardClose();
            }
            await Task.Delay(500, TestContext.Current.CancellationToken);
        }
        finally
        {
            harness.TryForwardClose();
        }
    }

    // ---- the data item must be a connected data item (0x00B1) ----

    [Theory]
    [InlineData(0x00B2)] // unconnected data item
    [InlineData(0x0000)] // null address item where data is expected
    public async Task Item07_PacketWithoutConnectedDataItem_IsIgnored(ushort dataItemType)
    {
        using var harness = new ImplicitHarness();
        harness.Client.ForwardOpen();
        try
        {
            await SendAndWaitUntilHandled(harness, ImplicitHarness.BuildTOPacket(ImplicitHarness.ConnectionIdTO, First, dataItemType: dataItemType));

            Assert.Equal(Zeros, Head(harness.Client));
        }
        finally
        {
            harness.TryForwardClose();
        }
    }

    // ---- sequence count: duplicates and stale packets must not overwrite newer data ----

    [Fact]
    public async Task Item07_DuplicateSequenceCount_IsIgnored()
    {
        using var harness = new ImplicitHarness();
        harness.Client.ForwardOpen();
        try
        {
            await harness.SendToOriginatorAsync(ImplicitHarness.BuildTOPacket(ImplicitHarness.ConnectionIdTO, First, sequence: 5), TestContext.Current.CancellationToken);
            WaitForData(harness.Client, First);

            await SendAndWaitUntilHandled(harness, ImplicitHarness.BuildTOPacket(ImplicitHarness.ConnectionIdTO, Second, sequence: 5));

            Assert.Equal(First, Head(harness.Client));
        }
        finally
        {
            harness.TryForwardClose();
        }
    }

    [Fact]
    public async Task Item07_OlderSequenceCount_IsIgnored()
    {
        using var harness = new ImplicitHarness();
        harness.Client.ForwardOpen();
        try
        {
            await harness.SendToOriginatorAsync(ImplicitHarness.BuildTOPacket(ImplicitHarness.ConnectionIdTO, First, sequence: 5), TestContext.Current.CancellationToken);
            WaitForData(harness.Client, First);

            await SendAndWaitUntilHandled(harness, ImplicitHarness.BuildTOPacket(ImplicitHarness.ConnectionIdTO, Second, sequence: 4));

            Assert.Equal(First, Head(harness.Client));
        }
        finally
        {
            harness.TryForwardClose();
        }
    }

    [Fact]
    public async Task Item07_NewerSequenceCount_IsAccepted()
    {
        // Guard for the fix: the check must not reject legitimate progress (passes today).
        using var harness = new ImplicitHarness();
        harness.Client.ForwardOpen();
        try
        {
            await harness.SendToOriginatorAsync(ImplicitHarness.BuildTOPacket(ImplicitHarness.ConnectionIdTO, First, sequence: 5), TestContext.Current.CancellationToken);
            WaitForData(harness.Client, First);

            await harness.SendToOriginatorAsync(ImplicitHarness.BuildTOPacket(ImplicitHarness.ConnectionIdTO, Second, sequence: 6), TestContext.Current.CancellationToken);

            WaitForData(harness.Client, Second);
        }
        finally
        {
            harness.TryForwardClose();
        }
    }

    [Fact]
    public async Task Item07_SequenceCountRollover_IsAccepted()
    {
        // Guard for the fix: the 16-bit class 1 count wraps 65535 -> 0 while the 32-bit number keeps counting (passes today).
        using var harness = new ImplicitHarness();
        harness.Client.ForwardOpen();
        try
        {
            await harness.SendToOriginatorAsync(ImplicitHarness.BuildTOPacket(ImplicitHarness.ConnectionIdTO, First, sequence: 65535), TestContext.Current.CancellationToken);
            WaitForData(harness.Client, First);

            await harness.SendToOriginatorAsync(ImplicitHarness.BuildTOPacket(ImplicitHarness.ConnectionIdTO, Second, sequence: 65536), TestContext.Current.CancellationToken);

            WaitForData(harness.Client, Second);
        }
        finally
        {
            harness.TryForwardClose();
        }
    }
}
