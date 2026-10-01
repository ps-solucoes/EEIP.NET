using System.Text;
using EEIP.NET.Tests.Fakes;
using Sres.Net.EEIP;

namespace EEIP.NET.Tests.SuspectedBugs;

/// <summary>Items 1-4 of the suspected-bug list: the object library decodes or addresses attributes wrongly.</summary>
[Trait("Category", "SuspectedBug")]
public sealed class ObjectLibraryBugTests : IDisposable
{
    private readonly FakeEipTarget target = new();
    private readonly EEIPClient client = new();

    public ObjectLibraryBugTests() => client.RegisterSession("127.0.0.1", target.Port);

    public void Dispose() => target.Dispose();

    private void Reply(byte[] path, params byte[] data) =>
        target.Handler = r => r.Path.SequenceEqual(path) ? CipReply.Ok(data) : CipReply.Error(0x05);

    // ---- Item 1: Message Router attributes 2-4 live on instance 1 (path 20 02 24 01 30 <attr>) ----

    [Fact]
    public void Item01_MessageRouter_NumberAvailable_ReadsAttribute2OfInstance1()
    {
        Reply([0x20, 0x02, 0x24, 0x01, 0x30, 0x02], 0x10, 0x00);

        Assert.Equal(16, client.MessageRouterObject.NumberAvailable);
    }

    [Fact]
    public void Item01_MessageRouter_NumberActive_ReadsAttribute3OfInstance1()
    {
        Reply([0x20, 0x02, 0x24, 0x01, 0x30, 0x03], 0x02, 0x00);

        Assert.Equal(2, client.MessageRouterObject.NumberActive);
    }

    [Fact]
    public void Item01_MessageRouter_ActiveConnections_ReadsAttribute4OfInstance1()
    {
        Reply([0x20, 0x02, 0x24, 0x01, 0x30, 0x04], 0x01, 0x00, 0x05, 0x00);

        Assert.Equal([1, 5], client.MessageRouterObject.ActiveConnections);
    }

    // ---- Item 2: bit 3 is "DHCP-DNS Update", bit 2 is "DHCP Client" ----

    [Theory]
    [InlineData(0x04, true, false)]
    [InlineData(0x08, false, true)]
    [InlineData(0x0C, true, true)]
    public void Item02_TcpIp_ConfigurationCapability_DhcpClientAndDhcpDnsUpdateAreSeparateBits(byte raw, bool dhcpClient, bool dhcpDnsUpdate)
    {
        Reply([0x20, 0xF5, 0x24, 0x01, 0x30, 0x02], raw, 0, 0, 0);

        var capability = client.TcpIpInterfaceObject.ConfigurationCapability;

        Assert.Equal(dhcpClient, capability.DHCPClient);
        Assert.Equal(dhcpDnsUpdate, capability.DHCP_DNSUpdate);
    }

    // ---- Item 3: attribute 4 is { UINT path size in words; padded EPATH } ----

    [Theory]
    [InlineData(new byte[] { 0x20, 0xF6, 0x24, 0x01 })]                   // 2 words: Ethernet Link instance 1
    [InlineData(new byte[] { 0x20, 0xF6, 0x24, 0x01, 0x30, 0x01 })]       // 3 words
    public void Item03_TcpIp_PhysicalLinkObject_ReturnsPathOfReportedSizeInWords(byte[] path)
    {
        Reply([0x20, 0xF5, 0x24, 0x01, 0x30, 0x04], [(byte)(path.Length / 2), 0x00, .. path]);

        var link = client.TcpIpInterfaceObject.PhysicalLinkObject;

        Assert.Equal(path.Length / 2, link.PathSize);
        Assert.Equal(path, link.Path);
    }

    // ---- Item 4: attribute 7 is a SHORT_STRING: one length byte, then the characters ----

    [Theory]
    [InlineData("750-352")]
    [InlineData("1756-ENBT/A")]
    [InlineData("")]
    public void Item04_Identity_ProductName_DropsShortStringLengthByte(string name)
    {
        Reply([0x20, 0x01, 0x24, 0x01, 0x30, 0x07], [(byte)name.Length, .. Encoding.ASCII.GetBytes(name)]);

        Assert.Equal(name, client.IdentityObject.ProductName);
    }
}
