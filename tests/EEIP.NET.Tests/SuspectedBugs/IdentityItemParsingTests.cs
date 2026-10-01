using EEIP.NET.Tests.Fakes;
using Sres.Net.EEIP;

namespace EEIP.NET.Tests.SuspectedBugs;

/// <summary>
/// Item 9: <c>CIPIdentityItem.getCIPIdentityItem</c> parses ListIdentity replies from arbitrary LAN hosts with
/// hard-coded offsets and no length checks.
/// </summary>
[Trait("Category", "SuspectedBug")]
public class IdentityItemParsingTests
{
    private static byte[] BuildListIdentityReply(string name, byte state, byte[]? trailing = null) =>
        ListIdentityResponder.BuildReply(name, state, trailing);

    [Theory]
    [InlineData("1756-ENBT/A", 3, new byte[] { 0xFF })]
    [InlineData("1756-ENBT/A", 2, new byte[] { 0x00, 0x00, 0x00 })]
    [InlineData("X", 4, new byte[] { 0xAA, 0xBB })]
    public void Item09_State_IsTheByteAfterTheProductName_NotTheLastByteOfThePacket(string name, byte state, byte[] trailing)
    {
        var item = Encapsulation.CIPIdentityItem.getCIPIdentityItem(24, BuildListIdentityReply(name, state, trailing));

        Assert.Equal(name, item.ProductName1);
        Assert.Equal(state, item.State1);
    }

    [Fact]
    public void Item09_ItemLength_BoundsTheItem()
    {
        // ItemLength is the number of bytes of the item following the length field; State1 must not read past it.
        var reply = BuildListIdentityReply("PLC", 3, trailing: [0x0C, 0x00, 0x00, 0x00, 0x02]);

        var item = Encapsulation.CIPIdentityItem.getCIPIdentityItem(24, reply);

        Assert.Equal(3, item.State1);
    }

    // Offsets are relative to the end of the 24 byte encapsulation header: item count (0-1), item type (2-3),
    // item length (4-5), version (6-7), socket address (8-23), vendor..status (24-33), serial (34-37),
    // name length (38), name (39-49), state (50).
    [Theory]
    [InlineData(0)]   // nothing at all after the encapsulation header
    [InlineData(2)]   // item count only
    [InlineData(6)]   // item header only
    [InlineData(20)]  // inside the socket address
    [InlineData(30)]  // inside vendor/device type/product code/revision/status
    [InlineData(36)]  // inside the serial number
    [InlineData(39)]  // name length present, name missing
    [InlineData(45)]  // inside the name
    public void Item09_TruncatedReply_IsRejectedCleanly(int bytesAfterHeader)
    {
        var reply = BuildListIdentityReply("1756-ENBT/A", 3)[..(24 + bytesAfterHeader)];

        Deliberate.AssertRejects(() => Encapsulation.CIPIdentityItem.getCIPIdentityItem(24, reply), $"reply cut after {bytesAfterHeader} bytes");
    }

    [Fact]
    public void Item09_MissingStateByte_IsRejectedCleanly()
    {
        var full = BuildListIdentityReply("PLC", 3);

        Deliberate.AssertRejects(() => Encapsulation.CIPIdentityItem.getCIPIdentityItem(24, full[..^1]), "state byte missing");
    }

    [Fact]
    public void Item09_ProductNameLengthLargerThanThePacket_IsRejectedCleanly()
    {
        var reply = BuildListIdentityReply("PLC", 3);
        reply[24 + 2 + 36] = 200; // claims a 200 byte name

        Deliberate.AssertRejects(() => Encapsulation.CIPIdentityItem.getCIPIdentityItem(24, reply), "name length exceeds packet");
    }
}
