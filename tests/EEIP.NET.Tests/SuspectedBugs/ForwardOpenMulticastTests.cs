using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using EEIP.NET.Tests.Fakes;
using Sres.Net.EEIP;

namespace EEIP.NET.Tests.SuspectedBugs;

/// <summary>
/// Item 5: <c>ForwardOpen</c> derives the multicast group from the target address with
/// <c>BitConverter.ToUInt32(GetAddressBytes())</c> (little-endian on x86) but <c>GetMulticastAddress</c> expects
/// host order, and the result then travels through the sockaddr item (big-endian on the wire) and
/// <c>new IPAddress(long)</c> (network order in memory). The byte order has to be right at every hop.
/// </summary>
[Trait("Category", "SuspectedBug")]
public sealed class ForwardOpenMulticastTests
{
    private static ImplicitHarness CreateHarness() => new(c =>
    {
        // Both directions: the multicast branch is guarded by one of the two connection types.
        c.O_T_ConnectionType = ConnectionType.Multicast;
        c.T_O_ConnectionType = ConnectionType.Multicast;
    });

    // CIP Vol. 2, 3-5.3 (same expectations as MulticastAddressTests, which feeds GetMulticastAddress directly).
    [Theory]
    [InlineData("127.0.0.1", new byte[] { 239, 192, 1, 0 })]    // class A, host 1
    [InlineData("10.0.0.2", new byte[] { 239, 192, 1, 32 })]    // class A, host 2
    [InlineData("172.16.0.1", new byte[] { 239, 192, 1, 0 })]   // class B, host 1
    [InlineData("192.168.1.10", new byte[] { 239, 192, 2, 32 })] // class C, host 10
    public void Item05_ForwardOpen_SockaddrItemCarriesTheCipMulticastGroupInNetworkOrder(string deviceAddress, byte[] expectedGroup)
    {
        using var harness = CreateHarness();
        // The session is already open on loopback; the property is only used for the multicast calculation. The
        // target rejects the connection so no UDP traffic is ever sent to the (fictitious) device address.
        harness.Client.IPAddress = deviceAddress;
        harness.Target.Handler = _ => CipReply.Error(0x01);

        Assert.Throws<CIPException>(() => harness.Client.ForwardOpen());

        var frame = Assert.Single(harness.Target.Requests).RawFrame;
        int dataLength = BinaryPrimitives.ReadUInt16LittleEndian(frame.AsSpan(38));
        var item = frame.AsSpan(40 + dataLength);
        Assert.Equal(0x8001, BinaryPrimitives.ReadUInt16LittleEndian(item));
        Assert.Equal(16, BinaryPrimitives.ReadUInt16LittleEndian(item[2..]));
        Assert.Equal(2, BinaryPrimitives.ReadUInt16BigEndian(item[4..]));                                   // AF_INET
        Assert.Equal(harness.Client.OriginatorUDPPort, BinaryPrimitives.ReadUInt16BigEndian(item[6..]));
        Assert.Equal(expectedGroup, item.Slice(8, 4).ToArray());
    }

    [Fact]
    public void Item05_ForwardOpen_JoinsTheMulticastGroupItAnnounced()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux() && File.Exists("/proc/net/igmp"), "needs /proc/net/igmp to observe group membership");
        AssumeMulticastCanBeJoined();

        using var harness = CreateHarness();
        harness.Client.ForwardOpen(); // throws today: the group handed to JoinMulticastGroup is not a multicast address
        try
        {
            // /proc/net/igmp prints groups as the in-memory (network order) bytes read as a little-endian word.
            Assert.Contains("0001C0EF", File.ReadAllText("/proc/net/igmp")); // 239.192.1.0 for 127.0.0.1
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
            probe.JoinMulticastGroup(IPAddress.Parse("239.192.1.0"));
        }
        catch (SocketException e)
        {
            Assert.Skip($"multicast groups cannot be joined in this environment: {e.Message}");
        }
    }
}
