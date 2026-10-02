using System.Buffers.Binary;
using EEIP.NET.Tests.Fakes;
using Sres.Net.EEIP;

namespace EEIP.NET.Tests.SuspectedBugs;

public enum ExplicitOp { GetAttributeSingle, GetAttributeAll, SetAttributeSingle }

/// <summary>
/// Item 6: TCP replies are read with a single <c>stream.Read</c> into a fixed buffer and the encapsulation header
/// (length, status) is never looked at.
/// <para>
/// Item 13: the receive code is copy-pasted into five request builders (plus RegisterSession), so every scenario
/// here is run against each of them; a fix that only touches one copy keeps some of these red.
/// </para>
/// </summary>
[Trait("Category", "SuspectedBug")]
public sealed class TcpReplyFramingTests : IDisposable
{
    private static readonly byte[] Payload = [0xDE, 0xAD, 0xBE, 0xEF];

    private readonly FakeEipTarget target = new();
    private readonly EEIPClient client = new();

    public void Dispose() => target.Dispose();

    private byte[] Run(ExplicitOp op) => op switch
    {
        ExplicitOp.GetAttributeSingle => client.GetAttributeSingle(0x01, 0x01, 0x07),
        ExplicitOp.GetAttributeAll => client.GetAttributeAll(0x01, 0x01),
        ExplicitOp.SetAttributeSingle => client.SetAttributeSingle(0x01, 0x01, 0x07, [0x00]),
        _ => throw new ArgumentOutOfRangeException(nameof(op)),
    };

    public static TheoryData<ExplicitOp, int[]> SplitCases()
    {
        var data = new TheoryData<ExplicitOp, int[]>();
        foreach (var op in Enum.GetValues<ExplicitOp>())
        {
            // 1, 10: inside the header; 24: header | body; 30: inside the CPF; 42, 43: before/after the general status;
            // 44: CIP header | data; 46: inside the data; [24, 44]: three segments.
            foreach (int at in new[] { 1, 10, 24, 30, 42, 43, 44, 46 })
                data.Add(op, [at]);
            data.Add(op, [24, 44]);
        }
        return data;
    }

    // ---- short reads ----

    [Theory]
    [MemberData(nameof(SplitCases))]
    public void Item06_ExplicitReply_SplitAcrossTcpWrites_IsReassembled(ExplicitOp op, int[] splitAt)
    {
        client.RegisterSession("127.0.0.1", target.Port);
        target.Handler = _ => CipReply.Ok(Payload);
        target.SplitReplyAt = splitAt;

        Assert.Equal(Payload, Run(op));
    }

    [Theory]
    [InlineData(4)]  // session handle not yet received
    [InlineData(6)]  // session handle cut in half
    [InlineData(8)]  // handle complete, rest of the reply still in flight
    [InlineData(24)] // header only
    public void Item06_RegisterSession_ReplySplitAcrossTcpWrites_IsReassembledAndLeavesNoStrayBytes(int splitAt)
    {
        target.SplitReplyAt = [splitAt];
        Assert.Equal(FakeEipTarget.SessionHandle, client.RegisterSession("127.0.0.1", target.Port));

        // Bytes of the RegisterSession reply that were never consumed would be mistaken for the next reply.
        target.SplitReplyAt = [];
        target.Handler = _ => CipReply.Ok(Payload);
        Assert.Equal(Payload, client.GetAttributeSingle(0x01, 0x01, 0x07));
    }

    // ---- replies larger than the 564 byte receive buffer ----

    [Theory]
    [InlineData(ExplicitOp.GetAttributeSingle, 521)] // 44 + 521 = 565: one byte over the buffer
    [InlineData(ExplicitOp.GetAttributeAll, 521)]
    [InlineData(ExplicitOp.SetAttributeSingle, 521)]
    [InlineData(ExplicitOp.GetAttributeSingle, 600)]
    [InlineData(ExplicitOp.GetAttributeAll, 4000)]
    [InlineData(ExplicitOp.SetAttributeSingle, 4000)]
    public void Item06_ExplicitReply_LargerThanReceiveBuffer_IsReturnedCompletely(ExplicitOp op, int length)
    {
        client.RegisterSession("127.0.0.1", target.Port);
        byte[] data = Enumerable.Range(0, length).Select(i => (byte)(i * 7)).ToArray();
        target.Handler = _ => CipReply.Ok(data);

        Assert.Equal(data, Run(op));
    }

    // ---- encapsulation header: status and length are authoritative ----

    public enum BadReply
    {
        /// <summary>Encapsulation status 0x64 (invalid session handle) on an otherwise well-formed reply.</summary>
        StatusWithBody,
        /// <summary>Encapsulation status 0x65 (invalid length) and nothing but the 24 byte header.</summary>
        StatusHeaderOnly,
        /// <summary>Success status but no CIP data at all.</summary>
        SuccessHeaderOnly,
        /// <summary>Success status, but the reply ends in the middle of the CPF.</summary>
        SuccessTruncatedCpf,
    }

    private static byte[] Truncate(byte[] frame, int length)
    {
        var truncated = frame[..length];
        BinaryPrimitives.WriteUInt16LittleEndian(truncated.AsSpan(2), (ushort)(length - 24));
        return truncated;
    }

    private static byte[] BuildBadReply(BadReply kind, CipRequest request) => kind switch
    {
        BadReply.StatusWithBody => FakeEipTarget.BuildSendRRDataReply(request.Service, CipReply.Ok(Payload), encapsulationStatus: 0x64),
        BadReply.StatusHeaderOnly => Truncate(FakeEipTarget.BuildSendRRDataReply(request.Service, CipReply.Ok(), encapsulationStatus: 0x65), 24),
        BadReply.SuccessHeaderOnly => Truncate(FakeEipTarget.BuildSendRRDataReply(request.Service, CipReply.Ok()), 24),
        BadReply.SuccessTruncatedCpf => Truncate(FakeEipTarget.BuildSendRRDataReply(request.Service, CipReply.Ok()), 34),
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    public static TheoryData<ExplicitOp, BadReply> BadReplyCases()
    {
        var data = new TheoryData<ExplicitOp, BadReply>();
        foreach (var op in Enum.GetValues<ExplicitOp>())
            foreach (var kind in Enum.GetValues<BadReply>())
                data.Add(op, kind);
        return data;
    }

    [Theory]
    [MemberData(nameof(BadReplyCases))]
    public void Item06_ExplicitReply_WithEncapsulationErrorOrShortFrame_FailsDeliberately(ExplicitOp op, BadReply kind)
    {
        client.RegisterSession("127.0.0.1", target.Port);
        target.RawReply = request => BuildBadReply(kind, request);

        Deliberate.AssertThrows(() => Run(op), kind.ToString());
    }

    [Theory]
    [InlineData(ExplicitOp.GetAttributeSingle)]
    [InlineData(ExplicitOp.GetAttributeAll)]
    [InlineData(ExplicitOp.SetAttributeSingle)]
    public void Item06_ExplicitReply_BytesBeyondTheEncapsulationLength_AreNotReturnedAsData(ExplicitOp op)
    {
        client.RegisterSession("127.0.0.1", target.Port);
        // The first four bytes of the next encapsulation message arrive glued to this reply.
        target.RawReply = request => [.. FakeEipTarget.BuildSendRRDataReply(request.Service, CipReply.Ok(Payload)), 0x6F, 0x00, 0x00, 0x00];

        Assert.Equal(Payload, Run(op));
    }

    // ---- Forward_Open / Forward_Close ----

    [Theory]
    [InlineData(10)]  // before the CIP general status
    [InlineData(24)]  // header only: connection ids not yet received
    [InlineData(43)]  // general status received, additional status size not
    [InlineData(44)]  // CIP header only
    [InlineData(48)]  // O->T connection id received, T->O connection id cut in half
    public async Task Item06_ForwardOpen_ReplySplitAcrossTcpWrites_UsesTheConnectionIdsOfTheReply(int splitAt)
    {
        using var harness = new ImplicitHarness();
        harness.Target.SplitReplyAt = [splitAt];
        harness.Client.ForwardOpen();
        try
        {
            var packet = await harness.ReceiveFromOriginatorAsync(TestContext.Current.CancellationToken);
            Assert.Equal(ImplicitHarness.ConnectionIdOT, BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(6)));

            await harness.SendToOriginatorAsync(ImplicitHarness.BuildTOPacket(ImplicitHarness.ConnectionIdTO, [0xCA, 0xFE, 0xBA, 0xBE]), TestContext.Current.CancellationToken);
            Assert.True(SpinWait.SpinUntil(() => harness.Client.T_O_IOData.AsSpan(0, 4).SequenceEqual(new byte[] { 0xCA, 0xFE, 0xBA, 0xBE }), ImplicitHarness.Timeout));
        }
        finally
        {
            harness.TryForwardClose();
        }
    }

    [Theory]
    [InlineData(10)]
    [InlineData(24)]
    [InlineData(42)] // general status is the next byte: it has not arrived yet
    public void Item06_ForwardClose_ErrorStatusInSplitReply_IsReported(int splitAt)
    {
        using var harness = new ImplicitHarness();
        harness.Client.ForwardOpen();
        harness.Target.Handler = request => request.Service == 0x4E ? CipReply.Error(0x01) : CipReply.Error(0x08);
        harness.Target.SplitReplyAt = [splitAt];

        Assert.Throws<CIPException>(() => harness.Client.ForwardClose());
    }

    // ---- Item 13 safety net: request framing of every builder (passes today, must keep passing when factored out) ----

    public static TheoryData<ConnectionType, ConnectionType, bool> ForwardOpenConfigurations() => new()
    {
        { ConnectionType.Point_to_Point, ConnectionType.Point_to_Point, false },
        { ConnectionType.Point_to_Point, ConnectionType.Point_to_Point, true },
        { ConnectionType.Null, ConnectionType.Point_to_Point, false },
        { ConnectionType.Point_to_Point, ConnectionType.Null, false },
    };

    [Theory]
    [MemberData(nameof(ForwardOpenConfigurations))]
    public void Item13_ForwardOpenAndForwardClose_FramesAreSelfConsistent(ConnectionType originToTarget, ConnectionType targetToOrigin, bool large)
    {
        using var harness = new ImplicitHarness(c =>
        {
            c.O_T_ConnectionType = originToTarget;
            c.T_O_ConnectionType = targetToOrigin;
        });
        if (large)
            harness.Client.LargeForwardOpen();
        else
            harness.Client.ForwardOpen();
        harness.Client.ForwardClose();

        var requests = harness.Target.Requests.ToArray();
        Assert.Equal(2, requests.Length);

        var open = requests[0].RawFrame;
        Assert.Equal(open.Length - 24, BinaryPrimitives.ReadUInt16LittleEndian(open.AsSpan(2)));
        Assert.Equal(3, BinaryPrimitives.ReadUInt16LittleEndian(open.AsSpan(30)));    // null address, data, sockaddr (T->O)
        Assert.Equal(0xB2, BinaryPrimitives.ReadUInt16LittleEndian(open.AsSpan(36)));
        int dataLength = BinaryPrimitives.ReadUInt16LittleEndian(open.AsSpan(38));
        Assert.Equal(open.Length - 40 - 20, dataLength);
        Assert.Equal(0x8001, BinaryPrimitives.ReadUInt16LittleEndian(open.AsSpan(40 + dataLength)));
        Assert.Equal(16, BinaryPrimitives.ReadUInt16LittleEndian(open.AsSpan(42 + dataLength)));
        Assert.Equal(large ? 0x5B : 0x54, open[40]);

        var close = requests[1].RawFrame;
        Assert.Equal(close.Length - 24, BinaryPrimitives.ReadUInt16LittleEndian(close.AsSpan(2)));
        Assert.Equal(2, BinaryPrimitives.ReadUInt16LittleEndian(close.AsSpan(30)));
        Assert.Equal(close.Length - 40, BinaryPrimitives.ReadUInt16LittleEndian(close.AsSpan(38)));
        Assert.Equal(0x4E, close[40]);
        // CIP: service, path size, path (4), priority, timeout, serial (2), vendor (2), originator serial (4) => path size at 16
        int connectionPathWords = close[40 + 16];
        Assert.Equal(connectionPathWords * 2, close.Length - (40 + 18));
    }
}
