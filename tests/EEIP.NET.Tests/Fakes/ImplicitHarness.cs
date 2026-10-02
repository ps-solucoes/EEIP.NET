using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Sres.Net.EEIP;

namespace EEIP.NET.Tests.Fakes;

/// <summary>
/// A <see cref="EEIPClient"/> with a registered session against a <see cref="FakeEipTarget"/> that answers
/// Forward_Open / Forward_Close, plus a UDP socket standing in for the target's I/O endpoint.
/// </summary>
public sealed class ImplicitHarness : IDisposable
{
    public const uint ConnectionIdOT = 0x0A0B0C0D;
    public const uint ConnectionIdTO = 0x01020304;
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

    public FakeEipTarget Target { get; } = new();
    public UdpClient TargetUdp { get; } = new(new IPEndPoint(IPAddress.Loopback, 0));
    public EEIPClient Client { get; }

    private readonly Action<EEIPClient>? configure;

    public ImplicitHarness(Action<EEIPClient>? configure = null)
    {
        this.configure = configure;
        Target.Handler = request => request.Service switch
        {
            0x54 or 0x5B => CipReply.Ok(ForwardOpenReplyData(request)),
            0x4E => CipReply.Ok(),
            _ => CipReply.Error(0x08),
        };
        Client = CreateRegisteredClient();
    }

    /// <summary>Another originator with the same configuration (own UDP port) and a session on the same target.</summary>
    public EEIPClient CreateRegisteredClient()
    {
        var client = new EEIPClient
        {
            O_T_ConnectionType = ConnectionType.Point_to_Point,
            T_O_ConnectionType = ConnectionType.Point_to_Point,
            O_T_Length = 4,
            T_O_Length = 4,
            RequestedPacketRate_O_T = 10_000,
            RequestedPacketRate_T_O = 10_000,
            TargetUDPPort = (ushort)((IPEndPoint)TargetUdp.Client.LocalEndPoint!).Port,
            OriginatorUDPPort = GetFreeUdpPort(),
        };
        configure?.Invoke(client);
        client.RegisterSession("127.0.0.1", Target.Port);
        return client;
    }

    public IPEndPoint OriginatorEndpoint => new(IPAddress.Loopback, Client.OriginatorUDPPort);

    public static byte[] ForwardOpenReplyData(CipRequest request) =>
    [
        .. LittleEndian(ConnectionIdOT), .. LittleEndian(ConnectionIdTO),
        .. request.Data[10..18],                          // connection serial, vendor, originator serial
        .. LittleEndian(10_000), .. LittleEndian(10_000), // actual packet rates
        0x00, 0x00,                                       // application reply size, reserved
    ];

    /// <summary>Calls ForwardClose, ignoring failures: used to stop the send thread when a test already failed.</summary>
    public void TryForwardClose()
    {
        Target.SplitReplyAt = [];
        Target.RawReply = null;
        try { Client.ForwardClose(); } catch (Exception) { }
    }

    /// <summary>
    /// Builds a Target-to-Originator class 1 packet: sequenced address item (type 0x8002) followed by a data item
    /// carrying the 16-bit class 1 sequence count and the payload. <paramref name="sequence"/> is used for both the
    /// 32-bit encapsulation sequence number and (truncated) the 16-bit class 1 sequence count, so both advance in
    /// lockstep and the 16-bit count rolls over at 65536.
    /// </summary>
    public static byte[] BuildTOPacket(uint connectionId, byte[] payload, uint sequence = 1, ushort dataItemType = 0x00B1)
    {
        var packet = new byte[20 + payload.Length];
        BinaryPrimitives.WriteUInt16LittleEndian(packet, 2);
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(2), 0x8002);
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(4), 8);
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(6), connectionId);
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(10), sequence);
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(14), dataItemType);
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(16), (ushort)(payload.Length + 2));
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(18), (ushort)sequence);
        payload.CopyTo(packet, 20);
        return packet;
    }

    public async Task SendToOriginatorAsync(byte[] packet, CancellationToken token = default) =>
        await TargetUdp.SendAsync(packet, OriginatorEndpoint, token);

    /// <summary>
    /// Sends a packet the client must ignore and checks for a while that neither the data nor LastReceivedImplicitMessage
    /// changes. Then a valid sentinel packet (with <paramref name="sentinelSequence"/>) follows: packets are handled in order,
    /// so once the sentinel's data shows up the ignored packet has been handled too, and the receive loop is still alive.
    /// Without the sentinel a dead receive loop would pass for one that ignores the packet.
    /// </summary>
    public async Task SendAndAssertIgnoredAsync(byte[] packet, uint sentinelSequence)
    {
        var token = TestContext.Current.CancellationToken;
        byte[] data = Client.T_O_IOData[..4];
        var stamp = Client.LastReceivedImplicitMessage;
        await SendToOriginatorAsync(packet, token);
        var window = Stopwatch.StartNew();
        while (window.Elapsed < TimeSpan.FromMilliseconds(300))
        {
            Assert.Equal(data, Client.T_O_IOData[..4]);
            Assert.Equal(stamp, Client.LastReceivedImplicitMessage);
            await Task.Delay(5, token);
        }

        byte[] sentinel = [0x5E, 0x47, 0x1E, 0x10];
        await SendToOriginatorAsync(BuildTOPacket(ConnectionIdTO, sentinel, sentinelSequence), token);
        Assert.True(SpinWait.SpinUntil(() => Client.T_O_IOData[..4].SequenceEqual(sentinel), Timeout),
            "the sentinel packet behind the ignored one was never handled: the receive loop no longer processes packets");
    }

    /// <summary>Receives the next O-to-T packet the client produces.</summary>
    public async Task<byte[]> ReceiveFromOriginatorAsync(CancellationToken token)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
        cts.CancelAfter(Timeout);
        return (await TargetUdp.ReceiveAsync(cts.Token)).Buffer;
    }

    public static byte[] LittleEndian(uint value)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, value);
        return bytes;
    }

    public static ushort GetFreeUdpPort()
    {
        using var probe = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
        return (ushort)((IPEndPoint)probe.Client.LocalEndPoint!).Port;
    }

    public void Dispose()
    {
        TargetUdp.Dispose();
        Target.Dispose();
    }
}
