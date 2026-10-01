using Sres.Net.EEIP;

namespace EEIP.NET.Tests;

public class EPathTests
{
    [Theory]
    [InlineData(0x01, 0x01, 0x07, new byte[] { 0x20, 0x01, 0x24, 0x01, 0x30, 0x07 })]
    [InlineData(0x04, 0x65, 0x03, new byte[] { 0x20, 0x04, 0x24, 0x65, 0x30, 0x03 })]
    [InlineData(0xFE, 0xFE, 0xFE, new byte[] { 0x20, 0xFE, 0x24, 0xFE, 0x30, 0xFE })]
    public void EightBitSegments(int classId, int instanceId, int attributeId, byte[] expected) =>
        Assert.Equal(expected, EEIPClient.GetEPath(classId, instanceId, attributeId));

    [Theory]
    [InlineData(0x0100, 0x01, 0x01, new byte[] { 0x21, 0x00, 0x00, 0x01, 0x24, 0x01, 0x30, 0x01 })]
    [InlineData(0x01, 0x0300, 0x01, new byte[] { 0x20, 0x01, 0x25, 0x00, 0x00, 0x03, 0x30, 0x01 })]
    [InlineData(0x01, 0x01, 0x1234, new byte[] { 0x20, 0x01, 0x24, 0x01, 0x31, 0x00, 0x34, 0x12 })]
    public void SixteenBitSegments_ArePaddedLittleEndian(int classId, int instanceId, int attributeId, byte[] expected) =>
        Assert.Equal(expected, EEIPClient.GetEPath(classId, instanceId, attributeId));

    [Fact]
    public void AttributeZero_OmitsAttributeSegment() =>
        Assert.Equal([0x20, 0x01, 0x24, 0x00], EEIPClient.GetEPath(1, 0, 0));
}

public class MulticastAddressTests
{
    // CIP Vol. 2, 3-5.3: base 239.192.1.0, index = (host id - 1) & 0x3FF, 32 addresses per index.
    [Theory]
    [InlineData("192.168.1.10", "239.192.2.32")] // class C, host 10
    [InlineData("172.16.0.1", "239.192.1.0")]    // class B, host 1
    [InlineData("10.0.0.2", "239.192.1.32")]     // class A, host 2
    [InlineData("10.0.4.1", "239.192.1.0")]      // host id 1025 wraps via the 0x3FF mask
    public void ClassfulDeviceAddress_MapsToCipMulticastRange(string device, string expected)
    {
        uint hostOrder = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(System.Net.IPAddress.Parse(device).GetAddressBytes());
        uint actual = EEIPClient.GetMulticastAddress(hostOrder);
        Assert.Equal(expected, Encapsulation.CIPIdentityItem.getIPAddress(actual));
    }
}

public class ConversionTests
{
    [Fact]
    public void ToUshort_IsLittleEndian() => Assert.Equal(0x1234, EEIPClient.ToUshort([0x34, 0x12]));

    [Fact]
    public void ToUint_IsLittleEndian() => Assert.Equal(0x12345678u, EEIPClient.ToUint([0x78, 0x56, 0x34, 0x12]));

    [Theory]
    [InlineData(0b0000_0001, 0, true)]
    [InlineData(0b0000_0001, 1, false)]
    [InlineData(0b1000_0000, 7, true)]
    [InlineData(0b0111_1111, 7, false)]
    public void ToBool_ReadsBit(byte input, int bit, bool expected) => Assert.Equal(expected, EEIPClient.ToBool(input, bit));

    [Theory]
    [InlineData(0x00, "Success")]
    [InlineData(0x08, "Service not supported")]
    [InlineData(0x14, "Attribute not supported")]
    [InlineData(0x2B, "Unknown Modbus Error")]
    [InlineData(0x2C, "unknown")]
    [InlineData(0xFF, "unknown")]
    public void GeneralStatusCodes_MapsKnownAndUnknownCodes(byte code, string expected) =>
        Assert.Equal(expected, GeneralStatusCodes.GetStatusCode(code));
}

public class IODataTests
{
    [Fact]
    public void O_T_IOData_ShorterValue_IsCopiedAndRemainderZeroed()
    {
        var client = new EEIPClient();
        client.O_T_IOData = Enumerable.Repeat((byte)0xFF, 505).ToArray();

        client.O_T_IOData = [1, 2, 3];

        var data = client.O_T_IOData;
        Assert.Equal(505, data.Length);
        Assert.Equal([1, 2, 3], data[..3]);
        Assert.All(data[3..], b => Assert.Equal(0, b));
    }

    [Fact]
    public void O_T_IOData_LongerValue_IsTruncated()
    {
        var client = new EEIPClient();
        client.O_T_IOData = Enumerable.Range(0, 600).Select(i => (byte)i).ToArray();
        Assert.Equal(Enumerable.Range(0, 505).Select(i => (byte)i), client.O_T_IOData);
    }

    [Fact]
    public void O_T_IOData_Null_ClearsBuffer()
    {
        var client = new EEIPClient();
        client.O_T_IOData = [1, 2, 3];
        client.O_T_IOData = null;
        Assert.All(client.O_T_IOData!, b => Assert.Equal(0, b));
    }

    [Fact]
    public void IOData_Getters_ReturnCopies()
    {
        var client = new EEIPClient();
        client.O_T_IOData[0] = 0xAA;
        client.T_O_IOData[0] = 0xAA;
        Assert.Equal(0, client.O_T_IOData[0]);
        Assert.Equal(0, client.T_O_IOData[0]);
    }
}
