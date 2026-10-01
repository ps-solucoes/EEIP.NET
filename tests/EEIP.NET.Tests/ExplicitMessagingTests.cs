using System.Buffers.Binary;
using EEIP.NET.Tests.Fakes;
using Sres.Net.EEIP;

namespace EEIP.NET.Tests;

public sealed class ExplicitMessagingTests : IDisposable
{
    private readonly FakeEipTarget target = new();
    private readonly EEIPClient client = new();

    public void Dispose() => target.Dispose();

    [Fact]
    public void RegisterSession_SendsProtocolVersion1AndReturnsTargetHandle()
    {
        uint handle = client.RegisterSession("127.0.0.1", target.Port);

        Assert.Equal(FakeEipTarget.SessionHandle, handle);
        Assert.Equal("127.0.0.1", client.IPAddress);
        var frame = Assert.Single(target.RegisterSessionFrames);
        Assert.Equal(0x65, BinaryPrimitives.ReadUInt16LittleEndian(frame));
        Assert.Equal(4, BinaryPrimitives.ReadUInt16LittleEndian(frame.AsSpan(2)));
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(4)));
        Assert.Equal([0x01, 0x00, 0x00, 0x00], frame[24..]);
    }

    [Fact]
    public void RegisterSession_WhenAlreadyRegistered_ReturnsCachedHandle()
    {
        client.RegisterSession("127.0.0.1", target.Port);
        Assert.Equal(FakeEipTarget.SessionHandle, client.RegisterSession("127.0.0.1", target.Port));
        Assert.Single(target.RegisterSessionFrames);
    }

    [Fact]
    public void GetAttributeSingle_WithoutSession_RegistersUsingConfiguredEndpoint()
    {
        client.IPAddress = "127.0.0.1";
        client.TCPPort = target.Port;
        target.Handler = _ => CipReply.Ok(0x01, 0x00);

        Assert.Equal([0x01, 0x00], client.GetAttributeSingle(1, 1, 1));
        Assert.Single(target.RegisterSessionFrames);
    }

    [Fact]
    public void GetAttributeSingle_SendsGetAttributeSingleWithSessionHandleAndPath()
    {
        client.RegisterSession("127.0.0.1", target.Port);
        target.Handler = _ => CipReply.Ok(0xDE, 0xAD, 0xBE, 0xEF);

        byte[] result = client.GetAttributeSingle(0x01, 0x01, 0x07);

        Assert.Equal([0xDE, 0xAD, 0xBE, 0xEF], result);
        var request = Assert.Single(target.Requests);
        Assert.Equal((byte)CIPCommonServices.Get_Attribute_Single, request.Service);
        Assert.Equal([0x20, 0x01, 0x24, 0x01, 0x30, 0x07], request.Path);
        Assert.Empty(request.Data);
        AssertSendRRDataFrameIsConsistent(request.RawFrame);
    }

    [Fact]
    public void GetAttributeAll_SendsGetAttributesAllWithoutAttributeSegment()
    {
        client.RegisterSession("127.0.0.1", target.Port);
        target.Handler = _ => CipReply.Ok(1, 2, 3);

        Assert.Equal([1, 2, 3], client.GetAttributeAll(0x01, 0x00));

        var request = Assert.Single(target.Requests);
        Assert.Equal((byte)CIPCommonServices.Get_Attributes_All, request.Service);
        Assert.Equal([0x20, 0x01, 0x24, 0x00], request.Path);
        AssertSendRRDataFrameIsConsistent(request.RawFrame);
    }

    [Fact]
    public void SetAttributeSingle_AppendsValueAfterPath()
    {
        client.RegisterSession("127.0.0.1", target.Port);

        Assert.Empty(client.SetAttributeSingle(0x04, 0x64, 0x03, [0x11, 0x22, 0x33]));

        var request = Assert.Single(target.Requests);
        Assert.Equal((byte)CIPCommonServices.Set_Attribute_Single, request.Service);
        Assert.Equal([0x20, 0x04, 0x24, 0x64, 0x30, 0x03], request.Path);
        Assert.Equal([0x11, 0x22, 0x33], request.Data);
        AssertSendRRDataFrameIsConsistent(request.RawFrame);
    }

    [Theory]
    [InlineData(0x14, "Attribute not supported")]
    [InlineData(0x05, "Path destination unknown")]
    public void NonZeroGeneralStatus_ThrowsCIPException(byte status, string message)
    {
        client.RegisterSession("127.0.0.1", target.Port);
        target.Handler = _ => CipReply.Error(status);

        Assert.Equal(message, Assert.Throws<CIPException>(() => client.GetAttributeSingle(1, 1, 1)).Message);
        Assert.Equal(message, Assert.Throws<CIPException>(() => client.GetAttributeAll(1, 1)).Message);
        Assert.Equal(message, Assert.Throws<CIPException>(() => client.SetAttributeSingle(1, 1, 1, [0])).Message);
    }

    [Fact]
    public void UnRegisterSession_SendsUnRegisterAndAllowsNewSession()
    {
        client.RegisterSession("127.0.0.1", target.Port);

        client.UnRegisterSession();

        Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref target.UnRegisterSessionCount) == 1, TimeSpan.FromSeconds(5)));
        client.RegisterSession("127.0.0.1", target.Port);
        Assert.Equal(2, target.RegisterSessionFrames.Count);
    }

    private static void AssertSendRRDataFrameIsConsistent(byte[] frame)
    {
        Assert.Equal(0x6F, BinaryPrimitives.ReadUInt16LittleEndian(frame));
        Assert.Equal(frame.Length - 24, BinaryPrimitives.ReadUInt16LittleEndian(frame.AsSpan(2)));
        Assert.Equal(FakeEipTarget.SessionHandle, BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(4)));
        Assert.Equal(2, BinaryPrimitives.ReadUInt16LittleEndian(frame.AsSpan(30)));
        Assert.Equal(0xB2, BinaryPrimitives.ReadUInt16LittleEndian(frame.AsSpan(36)));
        Assert.Equal(frame.Length - 40, BinaryPrimitives.ReadUInt16LittleEndian(frame.AsSpan(38)));
    }
}
