using Sres.Net.EEIP;

namespace EEIP.NET.Tests.SuspectedBugs;

/// <summary>Items 11 and 12: minor, spec-conformance flavoured findings in the static helpers.</summary>
[Trait("Category", "SuspectedBug")]
public class PathAndMulticastHelperBugTests
{
    // ---- Item 11: 0xFF fits an 8-bit segment, so the compact form should be used (tests the "< 0xff" boundary) ----

    [Theory]
    [InlineData(0xFF, 0x01, 0x01, new byte[] { 0x20, 0xFF, 0x24, 0x01, 0x30, 0x01 })]
    [InlineData(0x01, 0xFF, 0x01, new byte[] { 0x20, 0x01, 0x24, 0xFF, 0x30, 0x01 })]
    [InlineData(0x01, 0x01, 0xFF, new byte[] { 0x20, 0x01, 0x24, 0x01, 0x30, 0xFF })]
    public void Item11_GetEPath_Uses8BitSegmentForExactly0xFF(int classId, int instanceId, int attributeId, byte[] expected) =>
        Assert.Equal(expected, EEIPClient.GetEPath(classId, instanceId, attributeId));

    // ---- Item 12: class D (224/4) and class E (240/4) are not unicast host addresses ----
    // Contract chosen here: reject them. Today netmask stays 0, so the whole address is treated as the host id and
    // an in-range-looking multicast group is returned for an input that has no meaning.

    [Theory]
    [InlineData(0xE0000001u)] // 224.0.0.1
    [InlineData(0xEFC00101u)] // 239.192.1.1
    [InlineData(0xF0000001u)] // 240.0.0.1
    [InlineData(0xFFFFFFFEu)] // 255.255.255.254
    public void Item12_GetMulticastAddress_RejectsClassDAndEDeviceAddresses(uint deviceAddress) =>
        Assert.ThrowsAny<ArgumentException>(() => EEIPClient.GetMulticastAddress(deviceAddress));
}
