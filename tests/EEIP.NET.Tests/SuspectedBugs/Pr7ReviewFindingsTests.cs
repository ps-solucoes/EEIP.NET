using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using EEIP.NET.Tests.Fakes;
using Sres.Net.EEIP;

namespace EEIP.NET.Tests.SuspectedBugs;

/// <summary>
/// One failing test per verified finding of the code review of PR #7 (the fixes for issue #6). Every test here is red
/// until its finding is fixed, except the ones marked as guards.
/// </summary>
[Trait("Category", "Pr7Review")]
[Collection(NonParallelCollection.Name)]
public sealed class Pr7ReviewFindingsTests
{
    private static readonly byte[] First = [0xA1, 0xA2, 0xA3, 0xA4];

    private const byte ForwardOpenService = 0x54, LargeForwardOpenService = 0x5B, ForwardCloseService = 0x4E;

    private static void WaitForData(EEIPClient client, byte[] expected) =>
        Assert.True(SpinWait.SpinUntil(() => client.T_O_IOData[..expected.Length].SequenceEqual(expected), ImplicitHarness.Timeout),
            $"T_O_IOData never became {Convert.ToHexString(expected)}, is {Convert.ToHexString(client.T_O_IOData[..expected.Length])}");

    private static T GetPrivate<T>(object instance, string field) =>
        (T)instance.GetType().GetField(field, BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(instance)!;

    private static void SetPrivate(object instance, string field, object? value) =>
        instance.GetType().GetField(field, BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(instance, value);

    private static int Count(FakeEipTarget target, params byte[] services) =>
        target.Requests.Count(r => services.Contains(r.Service));

    /// <summary>A sockaddr info item (type 0x8001) as a target appends it to the Forward_Open reply; port and address in network order.</summary>
    private static byte[] SockaddrItem(ushort port, byte[] address)
    {
        var item = new byte[20];
        BinaryPrimitives.WriteUInt16LittleEndian(item, 0x8001);
        BinaryPrimitives.WriteUInt16LittleEndian(item.AsSpan(2), 16);
        BinaryPrimitives.WriteUInt16BigEndian(item.AsSpan(4), 2);     // AF_INET
        BinaryPrimitives.WriteUInt16BigEndian(item.AsSpan(6), port);
        address.CopyTo(item, 8);
        return item;
    }

    private static byte[] ForwardOpenReplyWithSockaddrItem(CipRequest request, byte[] sockaddrItem, int dataItemLengthError = 0)
    {
        var frame = FakeEipTarget.BuildSendRRDataReply(request.Service, CipReply.Ok(ImplicitHarness.ForwardOpenReplyData(request)), sockaddrItem, extraItemCount: 1);
        ushort declared = BinaryPrimitives.ReadUInt16LittleEndian(frame.AsSpan(38));
        BinaryPrimitives.WriteUInt16LittleEndian(frame.AsSpan(38), (ushort)(declared + dataItemLengthError));
        return frame;
    }

    // ---- one failed send ends the send thread for good ----

    [Fact]
    public async Task SendThread_AfterAFailedSend_KeepsSending()
    {
        // A send that fails once (a short network outage, ENOBUFS, ...) must not end O->T production for the rest of the
        // connection: the target would time it out. No socket error can be produced on demand on loopback, so the failure
        // is injected from the inside: with the lock of the output data gone, building the next packet throws.
        using var harness = new ImplicitHarness();
        var client = harness.Client;
        var token = TestContext.Current.CancellationToken;
        client.ForwardOpen();
        var realLock = GetPrivate<object>(client, "_O_T_IOData_lock");
        try
        {
            await harness.ReceiveFromOriginatorAsync(token);
            SetPrivate(client, "_O_T_IOData_lock", null);
            await Task.Delay(100, token);
            Assert.NotNull(client.ImplicitSendException);                   // reported while it lasts
            SetPrivate(client, "_O_T_IOData_lock", realLock);

            await Task.Delay(50, token);
            while (harness.TargetUdp.Available > 0)
                await harness.TargetUdp.ReceiveAsync(token);
            var exception = await Record.ExceptionAsync(() => harness.ReceiveFromOriginatorAsync(token));

            Assert.True(exception is null, "no O->T packet arrived after the failure: the send thread stopped for good");
            Assert.Null(client.ImplicitSendException);                      // and cleared once packets go out again
        }
        finally
        {
            SetPrivate(client, "_O_T_IOData_lock", realLock);
            harness.TryForwardClose();
        }
    }

    // ---- the receive socket is set up after the target accepted the connection ----

    [Fact]
    public void ForwardOpen_WhenTheReceivePortIsTaken_LeavesNoConnectionOpenOnTheTarget()
    {
        using var harness = new ImplicitHarness();
        var client = harness.Client;
        using (new UdpClient(new IPEndPoint(IPAddress.Any, client.OriginatorUDPPort)))
        {
            Assert.NotNull(Record.Exception(client.ForwardOpen));
        }

        // Binding first (nothing sent) or closing what was opened are both fine; an orphaned connection is not.
        int opened = Count(harness.Target, ForwardOpenService, LargeForwardOpenService);
        int closed = Count(harness.Target, ForwardCloseService);
        Assert.True(opened == closed, $"{opened} connection(s) opened on the target, {closed} closed");

        // And the client can try again once the port is free.
        client.ForwardOpen();
        harness.TryForwardClose();
    }

    // ---- T_O_Length is not checked against the 505 byte T->O buffer ----

    [Fact]
    public async Task ForwardOpen_WithAnInputLengthBeyondTheBuffer_IsRejectedUpFrontOrDelivered()
    {
        using var harness = new ImplicitHarness(c => c.T_O_Length = 600);
        var exception = Record.Exception(harness.Client.ForwardOpen);
        if (exception is not null)
        {
            Assert.False(Deliberate.IsAccident(exception), exception.ToString());
            Assert.Equal(0, Count(harness.Target, ForwardOpenService, LargeForwardOpenService));
            return;
        }
        try
        {
            // The connection was opened for 600 bytes of input, so 600 bytes of input must come through.
            var payload = new byte[600];
            First.CopyTo(payload, 0);
            await harness.SendToOriginatorAsync(ImplicitHarness.BuildTOPacket(ImplicitHarness.ConnectionIdTO, payload, sequence: 1), TestContext.Current.CancellationToken);

            WaitForData(harness.Client, First);
        }
        finally
        {
            harness.TryForwardClose();
        }
    }

    // ---- multicastAddress survives from one connection to the next ----

    [Fact]
    public void ForwardOpen_PointToPointAfterAMulticastConnection_DoesNotJoinTheOldGroup()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux() && File.Exists("/proc/net/igmp"), "needs /proc/net/igmp to observe group membership");
        AssumeMulticastCanBeJoined();
        const string Group = "014DC0EF";       // 239.192.77.1 in /proc/net/igmp notation (network order bytes as a little-endian word)

        using var harness = new ImplicitHarness(c => c.T_O_ConnectionType = ConnectionType.Multicast);
        var client = harness.Client;
        ushort targetPort = (ushort)((IPEndPoint)harness.TargetUdp.Client.LocalEndPoint!).Port;
        harness.Target.RawReply = request => request.Service == ForwardOpenService
            ? ForwardOpenReplyWithSockaddrItem(request, SockaddrItem(targetPort, [239, 192, 77, 1]))
            : null;
        client.ForwardOpen();
        try
        {
            Assert.Contains(Group, File.ReadAllText("/proc/net/igmp"));     // guard: the T->O group of the first connection is joined
        }
        finally
        {
            harness.TryForwardClose();
        }

        client.T_O_ConnectionType = ConnectionType.Point_to_Point;
        client.ForwardOpen();                                                // plain reply: no sockaddr item, no group
        try
        {
            Assert.DoesNotContain(Group, File.ReadAllText("/proc/net/igmp"));
        }
        finally
        {
            harness.TryForwardClose();
        }
    }

    private static void AssumeMulticastCanBeJoined()
    {
        try
        {
            using var probe = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
            probe.JoinMulticastGroup(IPAddress.Parse("239.192.77.2"));
        }
        catch (SocketException e)
        {
            Assert.Skip($"multicast groups cannot be joined in this environment: {e.Message}");
        }
    }

    // ---- WaitUntil without a high-resolution sleep (Windows before 1803) busy-yields ----

    [Fact]
    public void WaitUntil_WithoutAHighResolutionSleep_DoesNotBurnACoreAtA2msInterval()
    {
        using var sleeper = new PreciseSleeper();
        typeof(PreciseSleeper).GetField("<IsPrecise>k__BackingField", BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(sleeper, false);
        var waitUntil = typeof(EEIPClient).GetMethod("WaitUntil", BindingFlags.NonPublic | BindingFlags.Static)!;

        var process = Process.GetCurrentProcess();
        var cpuBefore = process.TotalProcessorTime;
        long interval = Stopwatch.Frequency / 500;          // 2 ms, as the send loop would wait at a 2 ms packet rate
        long start = Stopwatch.GetTimestamp(), next = start, end = start + Stopwatch.Frequency;
        while (next < end)
        {
            next += interval;
            waitUntil.Invoke(null, [next, CancellationToken.None, sleeper]);
        }
        process.Refresh();
        double cpuFraction = (process.TotalProcessorTime - cpuBefore).TotalSeconds / Stopwatch.GetElapsedTime(start).TotalSeconds;

        Assert.True(cpuFraction < 0.25, $"waiting out 2 ms intervals without a high-resolution sleep used {cpuFraction:P0} of a core");
    }

    // ---- ForwardOpen trusts the data item length to find the sockaddr item ----

    [Theory]
    [InlineData(0)]     // guard: correct length (passes today)
    [InlineData(4)]
    [InlineData(-2)]
    public void ForwardOpen_WithAWrongDataItemLength_StillFindsTheSockaddrItem(int dataItemLengthError)
    {
        // Wrong item lengths are common in devices; the Forward_Open reply data has a known size, so the sockaddr item behind
        // it can be found without trusting the length. Missing it sends the O->T data to the wrong port.
        using var harness = new ImplicitHarness();
        var client = harness.Client;
        ushort targetPort = (ushort)((IPEndPoint)harness.TargetUdp.Client.LocalEndPoint!).Port;
        client.TargetUDPPort = ImplicitHarness.GetFreeUdpPort();             // only the sockaddr item tells the right one
        harness.Target.RawReply = request => request.Service == ForwardOpenService
            ? ForwardOpenReplyWithSockaddrItem(request, SockaddrItem(targetPort, [127, 0, 0, 1]), dataItemLengthError)
            : null;

        client.ForwardOpen();
        try
        {
            Assert.Equal(targetPort, client.TargetUDPPort);
        }
        finally
        {
            harness.TryForwardClose();
        }
    }
}
