using System.Text;
using EEIP.NET.Tests.Fakes;
using Sres.Net.EEIP;
using Sres.Net.EEIP.ObjectLibrary;

namespace EEIP.NET.Tests;

public sealed class ObjectLibraryTests : IDisposable
{
    private readonly FakeEipTarget target = new();
    private readonly EEIPClient client = new();

    public ObjectLibraryTests() => client.RegisterSession("127.0.0.1", target.Port);

    public void Dispose() => target.Dispose();

    private void Reply(byte[] path, params byte[] data) =>
        target.Handler = r => r.Path.SequenceEqual(path) ? CipReply.Ok(data) : CipReply.Error(0x05);

    [Fact]
    public void Identity_ScalarAttributes()
    {
        target.Handler = r => r.Path switch
        {
            [0x20, 0x01, 0x24, 0x01, 0x30, 0x01] => CipReply.Ok(0x01, 0x00),
            [0x20, 0x01, 0x24, 0x01, 0x30, 0x02] => CipReply.Ok(0x0C, 0x00),
            [0x20, 0x01, 0x24, 0x01, 0x30, 0x03] => CipReply.Ok(0x34, 0x12),
            [0x20, 0x01, 0x24, 0x01, 0x30, 0x04] => CipReply.Ok(0x03, 0x07),
            [0x20, 0x01, 0x24, 0x01, 0x30, 0x05] => CipReply.Ok(0x60, 0x00),
            [0x20, 0x01, 0x24, 0x01, 0x30, 0x06] => CipReply.Ok(0x78, 0x56, 0x34, 0x12),
            [0x20, 0x01, 0x24, 0x01, 0x30, 0x08] => CipReply.Ok(0x03),
            _ => CipReply.Error(0x14),
        };
        var identity = client.IdentityObject;

        Assert.Equal(1, identity.VendorID);
        Assert.Equal(0x0C, identity.DeviceType);
        Assert.Equal(0x1234, identity.ProductCode);
        Assert.Equal(3, identity.Revision.MajorRevision);
        Assert.Equal(7, identity.Revision.MinorRevision);
        Assert.Equal(0x60, identity.Status);
        Assert.Equal(0x12345678u, identity.SerialNumber);
        Assert.Equal(IdentityObject.StateEnum.Operational, identity.State);
    }

    [Fact]
    public void Identity_InstanceAttributes_ParsesGetAttributesAllReply()
    {
        const string name = "750-352";
        Reply([0x20, 0x01, 0x24, 0x01],
            [0x21, 0x00, 0x0C, 0x00, 0x34, 0x12, 0x01, 0x02, 0x30, 0x00, 0x78, 0x56, 0x34, 0x12,
             (byte)name.Length, .. Encoding.ASCII.GetBytes(name)]);

        var attributes = client.IdentityObject.InstanceAttributes;

        Assert.Equal(0x21, attributes.VendorID);
        Assert.Equal(0x0C, attributes.DeviceType);
        Assert.Equal(0x1234, attributes.ProductCode);
        Assert.Equal(1, attributes.Revision.MajorRevision);
        Assert.Equal(2, attributes.Revision.MinorRevision);
        Assert.Equal(0x30, attributes.Status);
        Assert.Equal(0x12345678u, attributes.SerialNumber);
        Assert.Equal(name, attributes.ProductName);
    }

    [Fact]
    public void Identity_ClassAttributes_ParsesGetAttributesAllReply()
    {
        Reply([0x20, 0x01, 0x24, 0x00], 0x01, 0x00, 0x02, 0x00, 0x07, 0x00, 0x0C, 0x00);

        var attributes = client.IdentityObject.ClassAttributes;

        Assert.Equal(1, attributes.Revision);
        Assert.Equal(2, attributes.MaxInstance);
        Assert.Equal(7, attributes.MaxIDNumberOfClassAttributes);
        Assert.Equal(12, attributes.MaxIDNumberOfInstanceAttributes);
    }

    [Fact]
    public void MessageRouter_ObjectList()
    {
        Reply([0x20, 0x02, 0x24, 0x01, 0x30, 0x01], 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0xF5, 0x00);

        var list = client.MessageRouterObject.ObjectList;

        Assert.Equal(3, list.Number);
        Assert.Equal([0x01, 0x02, 0xF5], list.Classes);
    }

    [Theory]
    [InlineData(0x00, true, false, false, false)]
    [InlineData(0x01, false, true, false, false)]
    [InlineData(0x12, false, false, true, true)]
    public void TcpIp_Status(byte raw, bool notConfigured, bool valid, bool validManual, bool mcastPending)
    {
        Reply([0x20, 0xF5, 0x24, 0x01, 0x30, 0x01], raw, 0, 0, 0);

        var status = client.TcpIpInterfaceObject.Status;

        Assert.Equal(notConfigured, status.NotConfigured);
        Assert.Equal(valid, status.ValidConfiguration);
        Assert.Equal(validManual, status.ValidManualConfiguration);
        Assert.Equal(mcastPending, status.McastPending);
    }

    [Fact]
    public void TcpIp_ConfigurationCapability_BootPDnsSettable()
    {
        Reply([0x20, 0xF5, 0x24, 0x01, 0x30, 0x02], 0x13, 0, 0, 0);

        var capability = client.TcpIpInterfaceObject.ConfigurationCapability;

        Assert.True(capability.BootPClient);
        Assert.True(capability.DNSClient);
        Assert.True(capability.ConfigurationSettable);
        Assert.False(capability.DHCPClient);
    }

    [Theory]
    [InlineData(true, false, false, 0x01)]
    [InlineData(false, true, false, 0x02)]
    [InlineData(false, true, true, 0x12)]
    public void TcpIp_ConfigurationControl_WritesAttribute3(bool bootP, bool dhcp, bool dns, byte expected)
    {
        client.TcpIpInterfaceObject.ConfigurationControl = new InterfaceControlFlags { EnableBootP = bootP, EnableDHCP = dhcp, EnableDNS = dns };

        var request = Assert.Single(target.Requests);
        Assert.Equal([0x20, 0xF5, 0x24, 0x01, 0x30, 0x03], request.Path);
        Assert.Equal([expected, 0, 0, 0], request.Data);
    }

    [Fact]
    public void TcpIp_InterfaceConfiguration_WritesAttribute5()
    {
        client.TcpIpInterfaceObject.InterfaceConfiguration = new NetworkInterfaceConfiguration
        {
            IPAddress = 0x0A01A8C0,
            NetworkMask = 0x00FFFFFF,
            GatewayAddress = 0x0101A8C0,
            NameServer = 0x08080808,
            NameServer2 = 0x04040808,
            DomainName = "plant.local",
        };

        var request = Assert.Single(target.Requests);
        Assert.Equal([0x20, 0xF5, 0x24, 0x01, 0x30, 0x05], request.Path);
        Assert.Equal(68, request.Data.Length);
        Assert.Equal([0xC0, 0xA8, 0x01, 0x0A], request.Data[0..4]);
        Assert.Equal([0xFF, 0xFF, 0xFF, 0x00], request.Data[4..8]);
        Assert.Equal([0xC0, 0xA8, 0x01, 0x01], request.Data[8..12]);
        Assert.Equal([0x08, 0x08, 0x08, 0x08], request.Data[12..16]);
        Assert.Equal([0x08, 0x08, 0x04, 0x04], request.Data[16..20]);
        Assert.Equal("plant.local", Encoding.ASCII.GetString(request.Data, 20, 11));
        Assert.All(request.Data[31..], b => Assert.Equal(0, b));
    }

    [Fact]
    public void Assembly_GetAndSetInstance_UseAttribute3()
    {
        target.Handler = _ => CipReply.Ok(0xAA, 0xBB);

        Assert.Equal([0xAA, 0xBB], client.AssemblyObject.getInstance(0x65));
        client.AssemblyObject.setInstance(0x64, [0x01, 0x02]);

        var requests = target.Requests.ToArray();
        Assert.Equal((byte)CIPCommonServices.Get_Attribute_Single, requests[0].Service);
        Assert.Equal([0x20, 0x04, 0x24, 0x65, 0x30, 0x03], requests[0].Path);
        Assert.Equal((byte)CIPCommonServices.Set_Attribute_Single, requests[1].Service);
        Assert.Equal([0x20, 0x04, 0x24, 0x64, 0x30, 0x03], requests[1].Path);
        Assert.Equal([0x01, 0x02], requests[1].Data);
    }
}
