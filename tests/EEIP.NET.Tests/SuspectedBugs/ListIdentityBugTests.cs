using System.Net.Sockets;
using EEIP.NET.Tests.Fakes;
using Sres.Net.EEIP;

namespace EEIP.NET.Tests.SuspectedBugs;

/// <summary>
/// Item 10: <c>ListIdentity</c> keeps its result list in an instance field, never closes its UDP sockets and leaves
/// receives armed after it returned. Item 9 end to end: the same receive callback parses whatever a LAN host sends.
/// <para>
/// These tests need a real Ethernet/Wi-Fi interface with an IPv4 address (ListIdentity broadcasts on those) and a
/// free UDP port 44818; they skip themselves otherwise. Every call takes about one second per interface address.
/// </para>
/// </summary>
[Trait("Category", "SuspectedBug")]
[Collection(NonParallelCollection.Name)]
public sealed class ListIdentityBugTests
{
    private static readonly byte[] ValidReply = ListIdentityResponder.BuildReply("1756-ENBT/A", 3);

    private static ListIdentityResponder CreateResponderOrSkip()
    {
        Assert.SkipWhen(ListIdentityResponder.ExpectedRequestsPerListIdentityCall() == 0, "no up Ethernet/Wi-Fi interface with an IPv4 address");
        var responder = ListIdentityResponder.TryCreate();
        Assert.SkipWhen(responder is null, $"UDP port {ListIdentityResponder.Port} is in use");
        return responder!;
    }

    /// <summary>
    /// ListIdentity cannot run on Linux until <see cref="Extra_ListIdentity_SendsToTheDirectedBroadcastAddressWithoutThrowing"/>
    /// is fixed; the tests below say so instead of failing with an unrelated "Permission denied".
    /// </summary>
    private static List<Encapsulation.CIPIdentityItem> CallListIdentity(EEIPClient client)
    {
        try
        {
            return client.ListIdentity();
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.AccessDenied)
        {
            Assert.Fail("Blocked by the prerequisite bug Extra_ListIdentity_SendsToTheDirectedBroadcastAddressWithoutThrowing: " +
                        "ListIdentity throws SocketException(AccessDenied) because UdpClient.EnableBroadcast is never set.");
            throw;
        }
    }

    /// <summary>Calls ListIdentity, skipping if the broadcast never reached the responder (no local broadcast loopback).</summary>
    private static List<Encapsulation.CIPIdentityItem> ListIdentityOrSkip(EEIPClient client, ListIdentityResponder responder)
    {
        int requestsBefore = responder.Requests.Count;
        var result = CallListIdentity(client);
        Assert.SkipWhen(responder.Requests.Count == requestsBefore, "the ListIdentity broadcast did not reach the responder on this machine");
        return result;
    }

    // ---- Not on the original list: found while writing the tests above ----

    [Fact]
    public void Extra_ListIdentity_SendsToTheDirectedBroadcastAddressWithoutThrowing()
    {
        Assert.SkipWhen(ListIdentityResponder.ExpectedRequestsPerListIdentityCall() == 0, "no up Ethernet/Wi-Fi interface with an IPv4 address");

        // UdpClient only switches SO_BROADCAST on by itself for 255.255.255.255; ListIdentity sends to the directed
        // broadcast address of each interface, which Linux rejects with EACCES unless EnableBroadcast is set.
        var exception = Record.Exception(() => new EEIPClient().ListIdentity());

        Assert.Null(exception);
    }

    [Fact]
    public void Item10_ListIdentity_CalledTwice_ReturnsOnlyTheRepliesOfTheCurrentCall()
    {
        using var responder = CreateResponderOrSkip();
        responder.Replies = () => [ValidReply];
        var client = new EEIPClient();

        int firstCall = ListIdentityOrSkip(client, responder).Count;
        Assert.SkipWhen(firstCall == 0, "no reply made it back to the client");
        int secondCall = ListIdentityOrSkip(client, responder).Count;

        Assert.Equal(firstCall, secondCall);
    }

    [Fact]
    public void Item10_ListIdentity_ReturnsAnIndependentListPerCall()
    {
        using var responder = CreateResponderOrSkip();
        responder.Replies = () => [ValidReply];
        var client = new EEIPClient();

        var first = ListIdentityOrSkip(client, responder);
        int countAfterFirstCall = first.Count;
        Assert.SkipWhen(countAfterFirstCall == 0, "no reply made it back to the client");
        var second = ListIdentityOrSkip(client, responder);

        Assert.NotSame(first, second);
        Assert.Equal(countAfterFirstCall, first.Count); // the caller's list is not mutated by a later call
    }

    [Fact]
    public async Task Item10_ListIdentity_ReplyArrivingAfterTheCallReturned_DoesNotChangeTheReturnedList()
    {
        using var responder = CreateResponderOrSkip(); // stays silent during the call
        var client = new EEIPClient();

        var result = ListIdentityOrSkip(client, responder);
        Assert.Empty(result);

        foreach (var requester in responder.Requests)
            await responder.SendAsync(ValidReply, requester);
        await Task.Delay(500, TestContext.Current.CancellationToken);

        Assert.Empty(result); // a late reply goes to a socket that should have been closed
    }

    [Fact]
    public void Item10_ListIdentity_ClosesItsSockets()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "counts socket descriptors through /proc/self/fd");
        using var responder = CreateResponderOrSkip();
        var client = new EEIPClient();

        ListIdentityOrSkip(client, responder); // warm-up: creates whatever is created once per process
        int before = CountOpenSockets();
        ListIdentityOrSkip(client, responder);
        ListIdentityOrSkip(client, responder);
        int leaked = CountOpenSockets() - before;

        // Today every call leaves one UdpClient per interface address behind.
        Assert.InRange(leaked, int.MinValue, 1);
    }

    private static int CountOpenSockets() =>
        Directory.EnumerateFileSystemEntries("/proc/self/fd")
            .Count(path => new FileInfo(path).LinkTarget?.StartsWith("socket:", StringComparison.Ordinal) == true);

    // ---- Item 9 end to end: a malformed reply from any host on the LAN terminates the process ----

    [Fact]
    public async Task Item09_TruncatedListIdentityReply_DoesNotKillTheProcess()
    {
        using (CreateResponderOrSkip()) { } // only checks the environment: the child process binds the port itself

        await IsolatedScenario.AssertPassesAsync(typeof(ListIdentityBugTests), nameof(Scenario_TruncatedListIdentityReply), TestContext.Current.CancellationToken);
    }

    [Fact]
    public void Scenario_TruncatedListIdentityReply()
    {
        IsolatedScenario.SkipUnlessRequested(nameof(Scenario_TruncatedListIdentityReply));
        using var responder = ListIdentityResponder.TryCreate() ?? throw new InvalidOperationException("port in use");
        responder.Replies = () => [ValidReply[..30], ValidReply]; // garbage first, then a good answer
        var client = new EEIPClient();

        var result = CallListIdentity(client);

        Assert.NotEmpty(responder.Requests);
        Assert.All(result, item => Assert.Equal("1756-ENBT/A", item.ProductName1)); // only well-formed replies are listed
    }
}
