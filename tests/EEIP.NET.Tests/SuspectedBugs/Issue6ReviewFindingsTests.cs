using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using EEIP.NET.Tests.Fakes;
using Sres.Net.EEIP;

namespace EEIP.NET.Tests.SuspectedBugs;

/// <summary>
/// One failing test per verified finding of issue #6 (review of the EIPClient.cs fixes). Every test here is red
/// until its finding is fixed; the finding is named in the test.
/// </summary>
[Trait("Category", "Issue6")]
[Collection(NonParallelCollection.Name)]
public sealed class Issue6ReviewFindingsTests
{
    private static readonly byte[] Zeros = new byte[4];
    private static readonly byte[] First = [0xA1, 0xA2, 0xA3, 0xA4];
    private static readonly byte[] Second = [0xB1, 0xB2, 0xB3, 0xB4];

    private static byte[] Head(EEIPClient client) => client.T_O_IOData[..4];

    private static void WaitForData(EEIPClient client, byte[] expected) =>
        Assert.True(SpinWait.SpinUntil(() => Head(client).SequenceEqual(expected), ImplicitHarness.Timeout),
            $"T_O_IOData never became {Convert.ToHexString(expected)}, is {Convert.ToHexString(Head(client))}");

    private static T GetPrivate<T>(object instance, string field) =>
        (T)instance.GetType().GetField(field, BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(instance)!;

    private static void SetPrivate(object instance, string field, object? value) =>
        instance.GetType().GetField(field, BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(instance, value);

    private static int Count(FakeEipTarget target, params byte[] services) =>
        target.Requests.Count(r => services.Contains(r.Service));

    private const byte ForwardOpenService = 0x54, LargeForwardOpenService = 0x5B, ForwardCloseService = 0x4E;

    // ---- ForwardClose can throw before closing udpClientReceive ----

    public enum CloseFailure { CipErrorStatus, EncapsulationErrorStatus }

    [Theory]
    [InlineData(CloseFailure.CipErrorStatus)]
    [InlineData(CloseFailure.EncapsulationErrorStatus)]
    public void ForwardClose_WhenTheReplyIsAnError_StillClosesTheReceiveSocket(CloseFailure failure)
    {
        using var harness = new ImplicitHarness();
        var originalHandler = harness.Target.Handler;
        harness.Client.ForwardOpen();
        try
        {
            if (failure == CloseFailure.CipErrorStatus)
                harness.Target.Handler = request => request.Service == ForwardCloseService ? CipReply.Error(0x01) : originalHandler(request);
            else
                harness.Target.RawReply = request => request.Service == ForwardCloseService
                    ? FakeEipTarget.BuildSendRRDataReply(request.Service, CipReply.Ok(), encapsulationStatus: 0x65)
                    : null;

            Record.Exception(harness.Client.ForwardClose);   // reporting the error is fine, leaking the socket is not

            var exception = Record.Exception(() => new UdpClient(harness.OriginatorEndpoint.Port).Dispose());
            Assert.True(exception is null, "the originator UDP port is still bound after ForwardClose failed: " + exception);
        }
        finally
        {
            harness.Target.Handler = originalHandler;
            harness.TryForwardClose();
        }
    }

    // ---- constant 16-bit sequence count ----

    [Fact]
    public async Task SequenceFilter_DeviceWithConstantDataSequenceCount_StillDeliversData()
    {
        // The sequenced address item's 32-bit number advances; the 16-bit count in the data item stays at 0 (devices that
        // do not maintain it). Each packet is new data, so the filter must not drop everything after the first.
        using var harness = new ImplicitHarness();
        harness.Client.ForwardOpen();
        try
        {
            await SendWithConstantDataCount(harness, First, addressSequence: 1);
            WaitForData(harness.Client, First);

            await SendWithConstantDataCount(harness, Second, addressSequence: 2);

            WaitForData(harness.Client, Second);
        }
        finally
        {
            harness.TryForwardClose();
        }
    }

    private static async Task SendWithConstantDataCount(ImplicitHarness harness, byte[] payload, uint addressSequence)
    {
        var packet = ImplicitHarness.BuildTOPacket(ImplicitHarness.ConnectionIdTO, payload, addressSequence);
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(18), 0);
        await harness.SendToOriginatorAsync(packet, TestContext.Current.CancellationToken);
    }

    // ---- LastReceivedImplicitMessage is stamped for rejected packets ----

    [Theory]
    [InlineData("wrong connection id")]
    [InlineData("not a connected data item")]
    [InlineData("duplicate")]
    [InlineData("stale")]
    [InlineData("truncated")]
    [InlineData("oversized")]
    public async Task LastReceivedImplicitMessage_IsNotRefreshedByARejectedPacket(string kind)
    {
        using var harness = new ImplicitHarness();
        harness.Client.ForwardOpen();
        try
        {
            await harness.SendToOriginatorAsync(ImplicitHarness.BuildTOPacket(ImplicitHarness.ConnectionIdTO, First, sequence: 5), TestContext.Current.CancellationToken);
            WaitForData(harness.Client, First);
            await Task.Delay(100, TestContext.Current.CancellationToken);
            var stampOfLastAcceptedPacket = harness.Client.LastReceivedImplicitMessage;

            byte[] rejected = kind switch
            {
                "wrong connection id" => ImplicitHarness.BuildTOPacket(ImplicitHarness.ConnectionIdTO + 1, Second, sequence: 6),
                "not a connected data item" => ImplicitHarness.BuildTOPacket(ImplicitHarness.ConnectionIdTO, Second, sequence: 6, dataItemType: 0x00B2),
                "duplicate" => ImplicitHarness.BuildTOPacket(ImplicitHarness.ConnectionIdTO, Second, sequence: 5),
                "stale" => ImplicitHarness.BuildTOPacket(ImplicitHarness.ConnectionIdTO, Second, sequence: 4),
                "truncated" => new byte[10],
                "oversized" => ImplicitHarness.BuildTOPacket(ImplicitHarness.ConnectionIdTO, new byte[600], sequence: 6),
                _ => throw new ArgumentOutOfRangeException(nameof(kind)),
            };
            await harness.SendToOriginatorAsync(rejected, TestContext.Current.CancellationToken);
            await Task.Delay(300, TestContext.Current.CancellationToken);

            Assert.Equal(First, Head(harness.Client));
            Assert.Equal(stampOfLastAcceptedPacket, harness.Client.LastReceivedImplicitMessage);
        }
        finally
        {
            harness.TryForwardClose();
        }
    }

    // ---- a second ForwardOpen without ForwardClose ----

    [Theory]
    [InlineData(false)] // same originator UDP port: the second socket cannot be bound
    [InlineData(true)]  // another port: the second connection is set up next to the first
    public async Task SecondForwardOpenWithoutForwardClose_LeavesNothingBehindAfterOneForwardClose(bool changeOriginatorPort)
    {
        using var harness = new ImplicitHarness();
        var client = harness.Client;
        client.ForwardOpen();
        var firstSender = GetPrivate<CancellationTokenSource>(client, "sendCancellation");
        var firstReceiver = GetPrivate<UdpClient>(client, "udpClientReceive");
        try
        {
            if (changeOriginatorPort)
                client.OriginatorUDPPort = ImplicitHarness.GetFreeUdpPort();
            // Rejecting the call or replacing the connection are both fine; abandoning the first one is not.
            Record.Exception(client.ForwardOpen);
            Record.Exception(client.ForwardClose);

            // The target must not be left with a connection that nobody closes ...
            int opened = Count(harness.Target, ForwardOpenService, LargeForwardOpenService);
            int closed = Count(harness.Target, ForwardCloseService);
            Assert.True(opened == closed, $"{opened} connection(s) opened on the target, {closed} closed");

            // ... and no send thread may keep transmitting.
            await Task.Delay(200, TestContext.Current.CancellationToken);
            while (harness.TargetUdp.Available > 0)
                await harness.TargetUdp.ReceiveAsync(TestContext.Current.CancellationToken);
            await Task.Delay(300, TestContext.Current.CancellationToken);
            Assert.True(harness.TargetUdp.Available == 0, "the client still sends O->T packets after ForwardClose");
        }
        finally
        {
            firstSender.Cancel();       // whatever the client lost track of
            firstReceiver.Close();
            harness.TryForwardClose();
        }
    }

    // ---- ReadSendRRDataReply trusts the data item length ----

    [Theory]
    [InlineData("GetAttributeSingle", 10)]
    [InlineData("GetAttributeAll", 10)]
    [InlineData("GetAttributeSingle", -3)]
    [InlineData("GetAttributeAll", -3)]
    public void ExplicitReply_WithAWrongDataItemLength_ReturnsEverythingThatWasReceived(string call, int lengthError)
    {
        // Wrong item lengths are common in devices (ListIdentity already copes with them): the frame is what counts.
        byte[] payload = [1, 2, 3, 4, 5, 6];
        using var target = new FakeEipTarget();
        target.RawReply = request =>
        {
            var frame = FakeEipTarget.BuildSendRRDataReply(request.Service, CipReply.Ok(payload));
            ushort declared = BinaryPrimitives.ReadUInt16LittleEndian(frame.AsSpan(38));
            BinaryPrimitives.WriteUInt16LittleEndian(frame.AsSpan(38), (ushort)(declared + lengthError));
            return frame;
        };
        var client = new EEIPClient();
        client.RegisterSession("127.0.0.1", target.Port);

        byte[] result = call == "GetAttributeSingle" ? client.GetAttributeSingle(1, 1, 1) : client.GetAttributeAll(1, 1);

        Assert.Equal(payload, result);
    }

    // ---- receive loop exceptions are unobserved ----

    [Fact]
    public async Task ReceiveLoop_WhenHandlingAPacketThrows_KeepsReceiving()
    {
        // Nothing a datagram contains throws today, so the handler is made to fail from the inside: with its lock gone,
        // the packet that reaches Array.Copy faults. The loop must survive that and process the next packet.
        using var harness = new ImplicitHarness();
        var client = harness.Client;
        client.ForwardOpen();
        var realLock = GetPrivate<object>(client, "_T_O_IOData_lock");
        try
        {
            SetPrivate(client, "_T_O_IOData_lock", null);
            await harness.SendToOriginatorAsync(ImplicitHarness.BuildTOPacket(ImplicitHarness.ConnectionIdTO, First, sequence: 1), TestContext.Current.CancellationToken);
            await Task.Delay(300, TestContext.Current.CancellationToken);
            SetPrivate(client, "_T_O_IOData_lock", realLock);

            await harness.SendToOriginatorAsync(ImplicitHarness.BuildTOPacket(ImplicitHarness.ConnectionIdTO, Second, sequence: 2), TestContext.Current.CancellationToken);

            WaitForData(client, Second);
        }
        finally
        {
            SetPrivate(client, "_T_O_IOData_lock", realLock);
            harness.TryForwardClose();
        }
    }

    // ---- sendUDP is unguarded on a raw thread ----

    [Fact]
    public Task SendThread_WhenSendingFails_DoesNotKillTheProcess() =>
        IsolatedScenario.AssertPassesAsync(typeof(Issue6ReviewFindingsTests), nameof(Scenario_SendFails), TestContext.Current.CancellationToken);

    [Fact]
    public async Task Scenario_SendFails()
    {
        IsolatedScenario.SkipUnlessRequested(nameof(Scenario_SendFails));
        using var harness = new ImplicitHarness(c => c.TargetUDPPort = 0);     // sending to port 0 fails with a SocketException
        harness.Client.ForwardOpen();
        try
        {
            await Task.Delay(500, TestContext.Current.CancellationToken);
            Assert.IsType<SocketException>(harness.Client.ImplicitSendException);
        }
        finally
        {
            harness.TryForwardClose();
        }
    }

    [Fact]
    public Task SendThread_WithAnOutputLengthBeyondTheBuffer_DoesNotKillTheProcess() =>
        IsolatedScenario.AssertPassesAsync(typeof(Issue6ReviewFindingsTests), nameof(Scenario_OutputLengthBeyondTheBuffer), TestContext.Current.CancellationToken);

    [Fact]
    public async Task Scenario_OutputLengthBeyondTheBuffer()
    {
        IsolatedScenario.SkipUnlessRequested(nameof(Scenario_OutputLengthBeyondTheBuffer));
        using var harness = new ImplicitHarness(c => c.O_T_Length = 600);      // the O->T buffer holds 505 bytes
        Record.Exception(harness.Client.ForwardOpen);                          // rejecting the length up front is fine too
        try
        {
            await Task.Delay(500, TestContext.Current.CancellationToken);
        }
        finally
        {
            harness.TryForwardClose();
        }
    }

    // ---- WaitUntil busy-spins ----

    [Fact]
    public async Task SendThread_AtA2msPacketRate_DoesNotBurnACore()
    {
        using var harness = new ImplicitHarness(c => c.RequestedPacketRate_O_T = 2_000);
        harness.Client.ForwardOpen();
        double cpuFraction;
        try
        {
            await Task.Delay(200, TestContext.Current.CancellationToken);
            var process = Process.GetCurrentProcess();
            var cpuBefore = process.TotalProcessorTime;
            var wallBefore = Stopwatch.GetTimestamp();
            await Task.Delay(1000, TestContext.Current.CancellationToken);
            process.Refresh();
            cpuFraction = (process.TotalProcessorTime - cpuBefore).TotalSeconds / Stopwatch.GetElapsedTime(wallBefore).TotalSeconds;
        }
        finally
        {
            harness.TryForwardClose();
        }

        Assert.True(cpuFraction < 0.5, $"the process used {cpuFraction:P0} of a core to send a packet every 2 ms");
    }

    [Fact]
    public async Task SendThread_WithARequestedPacketRateOfZero_DoesNotFloodTheTarget()
    {
        using var harness = new ImplicitHarness(c => c.RequestedPacketRate_O_T = 0);
        if (Record.Exception(harness.Client.ForwardOpen) is not null)
            return;                                                           // rejecting a rate of 0 is fine
        uint? firstSequence = null, lastSequence = null;
        var stopwatch = Stopwatch.StartNew();
        try
        {
            using var window = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
            window.CancelAfter(TimeSpan.FromMilliseconds(300));
            try
            {
                while (true)
                {
                    var packet = (await harness.TargetUdp.ReceiveAsync(window.Token)).Buffer;
                    lastSequence = BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(10));
                    firstSequence ??= lastSequence;
                }
            }
            catch (OperationCanceledException) when (window.IsCancellationRequested) { }
        }
        finally
        {
            harness.TryForwardClose();
        }

        Assert.NotNull(firstSequence);
        double packetsPerSecond = (lastSequence!.Value - firstSequence!.Value) / stopwatch.Elapsed.TotalSeconds;
        Assert.True(packetsPerSecond <= 2000, $"{packetsPerSecond:F0} packets per second were sent for a requested rate of 0");
    }

    // ---- ListIdentity always sleeps one second ----

    [Fact]
    public void ListIdentity_WithNothingToListenOn_ReturnsWithoutWaiting()
    {
        // Needs a machine on which no broadcast can be sent at all, which is what leaves ListIdentity without receivers.
        Assert.SkipWhen(ListIdentityResponder.ExpectedRequestsPerListIdentityCall() > 0, "this machine has an up Ethernet/Wi-Fi interface with an IPv4 address");

        var stopwatch = Stopwatch.StartNew();
        var result = new EEIPClient().ListIdentity();

        Assert.Empty(result);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromMilliseconds(500), $"ListIdentity took {stopwatch.ElapsedMilliseconds} ms to find nothing to wait for");
    }
}
