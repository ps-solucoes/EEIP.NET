using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace EEIP.NET.Tests.Fakes;

/// <summary>
/// Listens on the EtherNet/IP UDP port and answers the broadcast <c>ListIdentity</c> requests of
/// <c>EEIPClient.ListIdentity</c> (sent to the broadcast address of every interface) with the configured replies.
/// </summary>
public sealed class ListIdentityResponder : IDisposable
{
    public const int Port = 44818;

    private readonly UdpClient udp;
    private readonly CancellationTokenSource cts = new();
    private readonly Task receiveLoop;

    /// <summary>Source endpoints of the ListIdentity requests received so far.</summary>
    public ConcurrentQueue<IPEndPoint> Requests { get; } = new();

    /// <summary>Datagrams sent back, in order, for every request. Empty: stay silent.</summary>
    public Func<IReadOnlyList<byte[]>> Replies { get; set; } = () => [];

    private ListIdentityResponder(UdpClient udp)
    {
        this.udp = udp;
        receiveLoop = Task.Run(ReceiveLoopAsync);
    }

    /// <summary>Null when the port cannot be bound (another EtherNet/IP stack on this machine).</summary>
    public static ListIdentityResponder? TryCreate()
    {
        var udp = new UdpClient(AddressFamily.InterNetwork);
        try
        {
            udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            udp.Client.Bind(new IPEndPoint(IPAddress.Any, Port));
            return new ListIdentityResponder(udp);
        }
        catch (SocketException)
        {
            udp.Dispose();
            return null;
        }
    }

    /// <summary>Number of broadcast requests <c>ListIdentity</c> sends: one per IPv4 address of each up Ethernet/Wi-Fi interface.</summary>
    public static int ExpectedRequestsPerListIdentityCall() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Where(ni => (ni.NetworkInterfaceType is NetworkInterfaceType.Wireless80211 or NetworkInterfaceType.Ethernet) && ni.OperationalStatus == OperationalStatus.Up)
            .Sum(ni => ni.GetIPProperties().UnicastAddresses.Count(a => a.Address.AddressFamily == AddressFamily.InterNetwork));

    public Task SendAsync(byte[] datagram, IPEndPoint to) => udp.SendAsync(datagram, to).AsTask();

    private async Task ReceiveLoopAsync()
    {
        try
        {
            while (!cts.IsCancellationRequested)
            {
                var received = await udp.ReceiveAsync(cts.Token);
                if (received.Buffer.Length < 24 || received.Buffer[0] != 0x63)
                    continue;
                Requests.Enqueue(received.RemoteEndPoint);
                foreach (var reply in Replies())
                    await udp.SendAsync(reply, received.RemoteEndPoint, cts.Token);
            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
        catch (SocketException) { }
    }

    /// <summary>A well-formed ListIdentity reply: encapsulation header plus one CIP Identity item (0x0C).</summary>
    public static byte[] BuildReply(string productName, byte state, byte[]? trailing = null)
    {
        var reply = new List<byte>(new byte[24]); // encapsulation header (command is irrelevant to the parser)
        reply[0] = 0x63;
        reply.AddRange([0x01, 0x00]);             // item count
        reply.AddRange([0x0C, 0x00]);             // item type
        reply.AddRange([(byte)(34 + productName.Length), 0x00]); // 32 fixed bytes + name length byte + name + state
        reply.AddRange([0x01, 0x00]);             // encapsulation protocol version
        reply.AddRange([0x00, 0x02, 0xAF, 0x12, 0xC0, 0xA8, 0x01, 0x0A]); // sockaddr (BE)
        reply.AddRange(new byte[8]);              // sin_zero
        reply.AddRange([0x01, 0x00, 0x0C, 0x00, 0x34, 0x12, 0x03, 0x07, 0x30, 0x00]); // vendor, type, code, revision, status
        reply.AddRange([0x78, 0x56, 0x34, 0x12]); // serial number
        reply.Add((byte)productName.Length);
        reply.AddRange(Encoding.ASCII.GetBytes(productName));
        reply.Add(state);
        if (trailing is not null)
            reply.AddRange(trailing);
        return [.. reply];
    }

    public void Dispose()
    {
        cts.Cancel();
        udp.Dispose();
        try { receiveLoop.Wait(TimeSpan.FromSeconds(5)); } catch (AggregateException) { }
        cts.Dispose();
    }
}
