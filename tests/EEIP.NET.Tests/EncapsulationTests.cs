using Sres.Net.EEIP;

namespace EEIP.NET.Tests;

public class EncapsulationTests
{
    [Fact]
    public void ToBytes_WritesLittleEndianHeaderFollowedByCommandSpecificData()
    {
        var encapsulation = new Encapsulation
        {
            Command = Encapsulation.CommandsEnum.RegisterSession,
            Length = 4,
            SessionHandle = 0xAABBCCDD,
        };
        encapsulation.CommandSpecificData.AddRange([1, 0, 0, 0]);

        byte[] expected =
        [
            0x65, 0x00,             // command
            0x04, 0x00,             // length
            0xDD, 0xCC, 0xBB, 0xAA, // session handle
            0x00, 0x00, 0x00, 0x00, // status
            0, 0, 0, 0, 0, 0, 0, 0, // sender context
            0x00, 0x00, 0x00, 0x00, // options
            0x01, 0x00, 0x00, 0x00, // protocol version, options
        ];
        Assert.Equal(expected, encapsulation.toBytes());
    }

    [Fact]
    public void CommonPacketFormat_ToBytes_WithoutSocketAddress_WritesTwoItems()
    {
        var cpf = new Encapsulation.CommonPacketFormat { DataItem = 0xB2, DataLength = 3 };
        cpf.Data.AddRange([0x0E, 0x01, 0x20]);

        byte[] expected =
        [
            0x02, 0x00,             // item count
            0x00, 0x00, 0x00, 0x00, // null address item
            0xB2, 0x00, 0x03, 0x00, // unconnected data item
            0x0E, 0x01, 0x20,
        ];
        Assert.Equal(expected, cpf.toBytes());
    }

    [Fact]
    public void CommonPacketFormat_ToBytes_WithSocketAddress_AppendsBigEndianSockaddrItem()
    {
        var cpf = new Encapsulation.CommonPacketFormat
        {
            DataLength = 1,
            SocketaddrInfo_O_T = new Encapsulation.SocketAddress
            {
                SIN_family = 2,
                SIN_port = 0x08AE,
                SIN_Address = 0xC0A8010A,
            },
        };
        cpf.Data.Add(0x54);

        byte[] bytes = cpf.toBytes();

        Assert.Equal(10 + 1 + 20, bytes.Length);
        Assert.Equal([0x03, 0x00], bytes[..2]);
        byte[] expectedItem =
        [
            0x01, 0x80, 0x10, 0x00, // type 0x8001 (T->O), length 16
            0x00, 0x02,             // sin_family (BE)
            0x08, 0xAE,             // sin_port (BE)
            0xC0, 0xA8, 0x01, 0x0A, // sin_addr (BE)
            0, 0, 0, 0, 0, 0, 0, 0, // sin_zero
        ];
        Assert.Equal(expectedItem, bytes[11..]);
    }

    [Fact]
    public void CIPIdentityItem_ParsesListIdentityReply()
    {
        const string name = "1756-ENBT/A";
        var reply = new List<byte>(new byte[24]); // encapsulation header
        reply.AddRange([0x01, 0x00]);             // item count
        reply.AddRange([0x0C, 0x00]);             // item type
        reply.AddRange([(byte)(33 + name.Length), 0x00]);
        reply.AddRange([0x01, 0x00]);             // encapsulation protocol version
        reply.AddRange([0x00, 0x02, 0xAF, 0x12, 0xC0, 0xA8, 0x01, 0x0A]); // sockaddr (BE)
        reply.AddRange(new byte[8]);              // sin_zero
        reply.AddRange([0x01, 0x00]);             // vendor id
        reply.AddRange([0x0C, 0x00]);             // device type
        reply.AddRange([0x34, 0x12]);             // product code
        reply.AddRange([0x03, 0x07]);             // revision
        reply.AddRange([0x30, 0x00]);             // status
        reply.AddRange([0x78, 0x56, 0x34, 0x12]); // serial number
        reply.Add((byte)name.Length);
        reply.AddRange(System.Text.Encoding.ASCII.GetBytes(name));
        reply.Add(0x03);                          // state

        var item = Encapsulation.CIPIdentityItem.getCIPIdentityItem(24, reply.ToArray());

        Assert.Equal(0x0C, item.ItemTypeCode);
        Assert.Equal(1, item.EncapsulationProtocolVersion);
        Assert.Equal(2, item.SocketAddress.SIN_family);
        Assert.Equal(0xAF12, item.SocketAddress.SIN_port);
        Assert.Equal(0xC0A8010Au, item.SocketAddress.SIN_Address);
        Assert.Equal(1, item.VendorID1);
        Assert.Equal(0x0C, item.DeviceType1);
        Assert.Equal(0x1234, item.ProductCode1);
        Assert.Equal([3, 7], item.Revision1);
        Assert.Equal(0x30, item.Status1);
        Assert.Equal(0x12345678u, item.SerialNumber1);
        Assert.Equal(name, item.ProductName1);
        Assert.Equal(3, item.State1);
    }

    [Theory]
    [InlineData(0xC0A8010Au, "192.168.1.10")]
    [InlineData(0x7F000001u, "127.0.0.1")]
    [InlineData(0xFFFFFFFFu, "255.255.255.255")]
    public void GetIPAddress_FormatsHostOrderAddress(uint address, string expected) =>
        Assert.Equal(expected, Encapsulation.CIPIdentityItem.getIPAddress(address));
}
