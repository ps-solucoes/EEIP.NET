using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace EEIP.NET.Tests.Fakes;

/// <summary>A CIP request as received by <see cref="FakeEipTarget"/> inside a SendRRData frame.</summary>
public sealed record CipRequest(byte Service, byte[] Path, byte[] Data, byte[] RawFrame);

/// <summary>The CIP reply <see cref="FakeEipTarget"/> sends back for a <see cref="CipRequest"/>.</summary>
public sealed record CipReply(byte GeneralStatus, byte[] Data, byte[]? AdditionalStatus = null)
{
    public static CipReply Ok(params byte[] data) => new(0, data);
    public static CipReply Error(byte status) => new(status, []);
}

/// <summary>
/// Minimal in-process EtherNet/IP target on loopback. Handles RegisterSession, UnRegisterSession
/// and SendRRData; the CIP layer is delegated to <see cref="Handler"/>.
/// </summary>
public sealed class FakeEipTarget : IDisposable
{
    public const uint SessionHandle = 0x11223344;

    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource cts = new();
    private readonly Task acceptLoop;

    public FakeEipTarget()
    {
        listener.Start();
        acceptLoop = Task.Run(AcceptLoopAsync);
    }

    public ushort Port => (ushort)((IPEndPoint)listener.LocalEndpoint).Port;

    public Func<CipRequest, CipReply> Handler { get; set; } = _ => CipReply.Ok();

    /// <summary>
    /// When set, the returned bytes are sent verbatim as the reply to a SendRRData request instead of the frame
    /// built from <see cref="Handler"/>. Return null to fall back to <see cref="Handler"/>.
    /// </summary>
    public Func<CipRequest, byte[]?>? RawReply { get; set; }

    /// <summary>
    /// Offsets into each reply frame (RegisterSession and SendRRData) at which the frame is cut into separate TCP
    /// writes, <see cref="ChunkDelay"/> apart. TCP is a byte stream, so a conforming originator must cope.
    /// </summary>
    public int[] SplitReplyAt { get; set; } = [];

    public TimeSpan ChunkDelay { get; set; } = TimeSpan.FromMilliseconds(50);

    public ConcurrentQueue<CipRequest> Requests { get; } = new();

    public ConcurrentQueue<byte[]> RegisterSessionFrames { get; } = new();

    public int UnRegisterSessionCount;

    private async Task AcceptLoopAsync()
    {
        try
        {
            while (!cts.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(cts.Token);
                _ = Task.Run(() => ServeAsync(client));
            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
        catch (SocketException) { }
    }

    private async Task ServeAsync(TcpClient client)
    {
        using var _ = client;
        client.NoDelay = true;
        var stream = client.GetStream();
        var header = new byte[24];
        try
        {
            while (!cts.IsCancellationRequested)
            {
                await stream.ReadExactlyAsync(header, cts.Token);
                ushort command = BinaryPrimitives.ReadUInt16LittleEndian(header);
                ushort length = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(2));
                var body = new byte[length];
                await stream.ReadExactlyAsync(body, cts.Token);
                byte[] frame = [.. header, .. body];

                switch (command)
                {
                    case 0x65: // RegisterSession
                        RegisterSessionFrames.Enqueue(frame);
                        var reply = (byte[])frame.Clone();
                        BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(4), SessionHandle);
                        await WriteReplyAsync(stream, reply, cts.Token);
                        break;
                    case 0x66: // UnRegisterSession: no reply, target closes
                        Interlocked.Increment(ref UnRegisterSessionCount);
                        return;
                    case 0x6F: // SendRRData
                        var request = ParseCipRequest(frame);
                        Requests.Enqueue(request);
                        var bytes = RawReply?.Invoke(request) ?? BuildSendRRDataReply(request.Service, Handler(request));
                        await WriteReplyAsync(stream, bytes, cts.Token);
                        break;
                    default:
                        return;
                }
            }
        }
        catch (EndOfStreamException) { }
        catch (OperationCanceledException) { }
        catch (IOException) { }
        catch (ObjectDisposedException) { }
    }

    private async Task WriteReplyAsync(NetworkStream stream, byte[] frame, CancellationToken token)
    {
        int start = 0;
        foreach (int at in SplitReplyAt.Where(at => at > 0 && at < frame.Length).Order())
        {
            await stream.WriteAsync(frame.AsMemory(start, at - start), token);
            await stream.FlushAsync(token);
            await Task.Delay(ChunkDelay, token);
            start = at;
        }
        await stream.WriteAsync(frame.AsMemory(start), token);
    }

    private static CipRequest ParseCipRequest(byte[] frame)
    {
        // 24 encapsulation header + 4 interface handle + 2 timeout + CPF:
        // item count (2), null address item (4), data item type (2), data length (2) => CIP at 40.
        ushort dataLength = BinaryPrimitives.ReadUInt16LittleEndian(frame.AsSpan(38));
        var cip = frame.AsSpan(40, dataLength);
        int pathBytes = cip[1] * 2;
        return new CipRequest(cip[0], cip.Slice(2, pathBytes).ToArray(), cip[(2 + pathBytes)..].ToArray(), frame);
    }

    public static byte[] BuildSendRRDataReply(byte requestService, CipReply reply, byte[]? extraItems = null, ushort extraItemCount = 0, uint encapsulationStatus = 0)
    {
        var additional = reply.AdditionalStatus ?? [];
        int cipLength = 4 + additional.Length + reply.Data.Length;
        extraItems ??= [];
        var frame = new byte[40 + cipLength + extraItems.Length];
        var span = frame.AsSpan();

        BinaryPrimitives.WriteUInt16LittleEndian(span, 0x6F);
        BinaryPrimitives.WriteUInt16LittleEndian(span[2..], (ushort)(frame.Length - 24));
        BinaryPrimitives.WriteUInt32LittleEndian(span[4..], SessionHandle);
        BinaryPrimitives.WriteUInt32LittleEndian(span[8..], encapsulationStatus);
        BinaryPrimitives.WriteUInt16LittleEndian(span[30..], (ushort)(2 + extraItemCount));
        BinaryPrimitives.WriteUInt16LittleEndian(span[36..], 0xB2);
        BinaryPrimitives.WriteUInt16LittleEndian(span[38..], (ushort)cipLength);
        span[40] = (byte)(requestService | 0x80);
        span[42] = reply.GeneralStatus;
        span[43] = (byte)(additional.Length / 2);
        additional.CopyTo(span[44..]);
        reply.Data.CopyTo(span[(44 + additional.Length)..]);
        extraItems.CopyTo(span[(40 + cipLength)..]);
        return frame;
    }

    public void Dispose()
    {
        cts.Cancel();
        listener.Stop();
        try { acceptLoop.Wait(TimeSpan.FromSeconds(5)); } catch (AggregateException) { }
        cts.Dispose();
    }
}
