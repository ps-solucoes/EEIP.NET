using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using EEIP.NET.Tests.Fakes;
using Sres.Net.EEIP;

namespace EEIP.NET.Tests;

public sealed class ImplicitMessagingTests : IDisposable
{
    private const uint ConnectionIdOT = 0x0A0B0C0D;
    private const uint ConnectionIdTO = 0x01020304;
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

    private readonly FakeEipTarget target = new();
    private readonly UdpClient targetUdp = new(new IPEndPoint(IPAddress.Loopback, 0));
    private readonly EEIPClient client = new()
    {
        O_T_ConnectionType = ConnectionType.Point_to_Point,
        T_O_ConnectionType = ConnectionType.Point_to_Point,
        O_T_Length = 4,
        T_O_Length = 4,
        RequestedPacketRate_O_T = 10_000,
        RequestedPacketRate_T_O = 10_000,
    };

    public ImplicitMessagingTests()
    {
        client.TargetUDPPort = (ushort)((IPEndPoint)targetUdp.Client.LocalEndPoint!).Port;
        client.OriginatorUDPPort = GetFreeUdpPort();
        target.Handler = request => request.Service switch
        {
            0x54 => CipReply.Ok(
            [
                .. LittleEndian(ConnectionIdOT), .. LittleEndian(ConnectionIdTO),
                .. request.Data[10..18],                  // connection serial, vendor, originator serial
                .. LittleEndian(10_000), .. LittleEndian(10_000), // actual packet rates
                0x00, 0x00,                               // application reply size, reserved
            ]),
            0x4E => CipReply.Ok(),
            _ => CipReply.Error(0x08),
        };
        client.RegisterSession("127.0.0.1", target.Port);
    }

    public void Dispose()
    {
        targetUdp.Dispose();
        target.Dispose();
    }

    [Fact]
    public void ForwardOpen_SendsExpectedConnectionParameters()
    {
        client.ForwardOpen();
        try
        {
            var request = Assert.Single(target.Requests);
            Assert.Equal(0x54, request.Service);
            Assert.Equal([0x20, 0x06, 0x24, 0x01], request.Path);

            var data = request.Data;
            Assert.Equal(10_000u, BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(22)));
            Assert.Equal(10_000u, BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(28)));
            // redundant owner | P2P | scheduled | variable | size (4 data + 2 seq + 4 run/idle header)
            Assert.Equal(0xCA0A, BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(26)));
            // redundant owner | P2P | scheduled | variable | size (4 data + 2 seq, modeless)
            Assert.Equal(0xCA06, BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(32)));
            Assert.Equal(0x01, data[34]); // class 1, cyclic
            Assert.Equal(4, data[35]);    // connection path size in words
            Assert.Equal([0x20, 0x04, 0x24, 0x01, 0x2C, 0x64, 0x2C, 0x65], data[36..44]);
        }
        finally
        {
            client.ForwardClose();
        }
    }

    [Fact]
    public async Task ForwardOpen_ExchangesCyclicIOData_AndForwardCloseTearsDown()
    {
        client.O_T_IOData = [0x11, 0x22, 0x33, 0x44];
        client.ForwardOpen();

        // O->T: originator produces cyclically with the connection id assigned by the target.
        using (var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken))
        {
            cts.CancelAfter(Timeout);
            var packet = (await targetUdp.ReceiveAsync(cts.Token)).Buffer;
            Assert.Equal(4 + 20 + 4, packet.Length);
            Assert.Equal(ConnectionIdOT, BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(6)));
            Assert.Equal([0xB1, 0x00], packet[14..16]);
            Assert.Equal(4 + 2 + 4, BinaryPrimitives.ReadUInt16LittleEndian(packet.AsSpan(16)));
            Assert.Equal([0x01, 0x00, 0x00, 0x00], packet[20..24]); // run/idle header: run
            Assert.Equal([0x11, 0x22, 0x33, 0x44], packet[24..28]);
        }

        // T->O: packets carrying the T->O connection id land in T_O_IOData; others are ignored.
        var originator = new IPEndPoint(IPAddress.Loopback, client.OriginatorUDPPort);
        await targetUdp.SendAsync(BuildTOPacket(ConnectionIdTO + 1, [0xEE, 0xEE, 0xEE, 0xEE]), originator, TestContext.Current.CancellationToken);
        await targetUdp.SendAsync(BuildTOPacket(ConnectionIdTO, [0xCA, 0xFE, 0xBA, 0xBE]), originator, TestContext.Current.CancellationToken);
        Assert.True(SpinWait.SpinUntil(() => client.T_O_IOData.AsSpan(0, 4).SequenceEqual(new byte[] { 0xCA, 0xFE, 0xBA, 0xBE }), Timeout));

        client.ForwardClose();

        var close = target.Requests.Last();
        Assert.Equal(0x4E, close.Service);
        Assert.Equal([0x20, 0x06, 0x24, 0x01], close.Path);
        Assert.Equal(target.Requests.First().Data[10..12], close.Data[2..4]); // connection serial matches the open
        Assert.Equal([0x20, 0x04, 0x24, 0x01, 0x2C, 0x64, 0x2C, 0x65], close.Data[^8..]);
    }

    private static byte[] BuildTOPacket(uint connectionId, byte[] payload)
    {
        var packet = new byte[20 + payload.Length];
        BinaryPrimitives.WriteUInt16LittleEndian(packet, 2);
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(2), 0x8002);
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(4), 8);
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(6), connectionId);
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(10), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(14), 0x00B1);
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(16), (ushort)(payload.Length + 2));
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(18), 1);
        payload.CopyTo(packet, 20);
        return packet;
    }

    private static byte[] LittleEndian(uint value)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, value);
        return bytes;
    }

    private static ushort GetFreeUdpPort()
    {
        using var probe = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
        return (ushort)((IPEndPoint)probe.Client.LocalEndPoint!).Port;
    }
}
