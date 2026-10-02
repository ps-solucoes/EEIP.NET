using System.Buffers.Binary;
using System.Diagnostics;
using EEIP.NET.Tests.Fakes;

namespace EEIP.NET.Tests.SuspectedBugs;

/// <summary>Item 8: the O-to-T send thread (<c>sendUDP</c>).</summary>
[Trait("Category", "SuspectedBug")]
[Collection(NonParallelCollection.Name)]
public sealed class ImplicitSendBugTests
{
    // ---- timing: Thread.Sleep(RPI / 1000) truncates and ignores the time spent building and sending ----

    [Theory]
    [InlineData(500u)]  // < 1 ms: Sleep(0), the thread spins and floods the network
    [InlineData(1500u)] // Sleep(1): sends every ~1.1 ms instead of every 1.5 ms
    public async Task Item08_SendInterval_FollowsTheRequestedPacketRate(uint requestedPacketRateMicroseconds)
    {
        using var harness = new ImplicitHarness(c => c.RequestedPacketRate_O_T = requestedPacketRateMicroseconds);
        harness.Client.ForwardOpen();
        var samples = new List<(long Timestamp, uint Sequence)>();
        try
        {
            using var window = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
            window.CancelAfter(TimeSpan.FromMilliseconds(800));
            try
            {
                while (true)
                {
                    var packet = (await harness.TargetUdp.ReceiveAsync(window.Token)).Buffer;
                    samples.Add((Stopwatch.GetTimestamp(), BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(10))));
                }
            }
            catch (OperationCanceledException) when (window.IsCancellationRequested) { }
        }
        finally
        {
            harness.TryForwardClose();
        }

        Assert.True(samples.Count >= 2, "no packets received");
        var (first, last) = (samples[0], samples[^1]);
        // The sequence number counts packets sent, so datagrams dropped by a flooded receive buffer do not matter.
        double sentPackets = last.Sequence - first.Sequence;
        Assert.True(sentPackets >= 10, $"only {sentPackets} packets sent in the window");
        double actualMicroseconds = (last.Timestamp - first.Timestamp) * 1_000_000.0 / Stopwatch.Frequency / sentPackets;

        Assert.InRange(actualMicroseconds, requestedPacketRateMicroseconds * 0.8, requestedPacketRateMicroseconds * 1.2);
    }

    // ---- efficiency: nothing in the loop needs to be allocated per packet ----

    [Fact]
    public async Task Item08_SendLoop_DoesNotAllocatePerPacket()
    {
        var window = TimeSpan.FromSeconds(1);
        using var harness = new ImplicitHarness(c => c.RequestedPacketRate_O_T = 2_000); // ~500 packets per window

        // What the test process allocates by itself over an idle window.
        long idleBefore = GC.GetTotalAllocatedBytes(precise: true);
        await Task.Delay(window, TestContext.Current.CancellationToken);
        long idle = GC.GetTotalAllocatedBytes(precise: true) - idleBefore;

        harness.Client.ForwardOpen();
        try
        {
            await Task.Delay(200, TestContext.Current.CancellationToken); // warm up
            long before = GC.GetTotalAllocatedBytes(precise: true);
            await Task.Delay(window, TestContext.Current.CancellationToken);
            long sending = GC.GetTotalAllocatedBytes(precise: true) - before;

            // Today: a 564 byte buffer, an IPEndPoint, a parsed IPAddress and a UdpState per packet (~0.8 KB).
            Assert.InRange(sending - idle, long.MinValue, 32 * 1024);
        }
        finally
        {
            harness.TryForwardClose();
        }
    }

    // ---- lifetime: ForwardClose can be overwritten by the thread it is meant to stop ----

    [Fact]
    public async Task Item08_ForwardClose_RightAfterForwardOpen_StopsTheSendThread()
    {
        using var harness = new ImplicitHarness();
        var clients = new List<Sres.Net.EEIP.EEIPClient>();
        try
        {
            // sendUDP does "stopUDP = false" as its first act on the new thread; a ForwardClose that wins that race is lost.
            // One client per round: re-opening on the same client is a different crash (see ImplicitReceiveBugTests).
            for (int i = 0; i < 20; i++)
            {
                var client = harness.CreateRegisteredClient();
                clients.Add(client);
                client.ForwardOpen();
                client.ForwardClose();
            }

            await Task.Delay(300, TestContext.Current.CancellationToken); // packets already in flight
            Drain(harness);
            await Task.Delay(300, TestContext.Current.CancellationToken);

            Assert.True(harness.TargetUdp.Available == 0, "a send thread is still producing O->T packets after ForwardClose");
        }
        finally
        {
            // Stops any thread that survived; it would otherwise keep the test host alive.
            harness.Target.Handler = _ => CipReply.Ok();
            foreach (var client in clients)
                try { client.ForwardClose(); } catch (Exception) { }
        }
    }

    private static void Drain(ImplicitHarness harness)
    {
        var buffer = new byte[2048];
        while (harness.TargetUdp.Available > 0)
            harness.TargetUdp.Client.Receive(buffer);
    }
}
