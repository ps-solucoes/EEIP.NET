# Suspected bugs: failing tests

Every test here is tagged `[Trait("Category", "SuspectedBug")]` and is **expected to fail** until the matching bug is
fixed (`Item<NN>_` in the test name is the number from the review list). Run only these, or everything else:

```
dotnet test tests/EEIP.NET.Tests --filter "Category=SuspectedBug"
dotnet test tests/EEIP.NET.Tests --filter "Category!=SuspectedBug"
```

A few tests pass today on purpose; they pin behaviour a fix must not break: `Item02` (`0x04` row), `Item07_NewerSequenceCount_IsAccepted`,
`Item07_SequenceCountRollover_IsAccepted` and `Item13_*` (request framing of every builder, a safety net for factoring them out).

## Item to test

| # | Where | Notes |
|---|-------|-------|
| 1 | `ObjectLibraryBugTests` | MessageRouter attributes 2-4 are read from the wrong path |
| 2 | `ObjectLibraryBugTests` | bit `0x08` must set `DHCP_DNSUpdate`, not `DHCPClient` |
| 3 | `ObjectLibraryBugTests` | `PhysicalLinkObject` throws; path size is in words |
| 4 | `ObjectLibraryBugTests` | `ProductName` keeps the SHORT_STRING length byte |
| 5 | `ForwardOpenMulticastTests` | sockaddr item bytes (all address classes, loopback-safe) and the group actually joined (Linux, reads `/proc/net/igmp`) |
| 6 | `TcpReplyFramingTests` | split replies, replies over 564 bytes, encapsulation status and length, for `RegisterSession`, `GetAttributeSingle`, `GetAttributeAll`, `SetAttributeSingle`, `ForwardOpen`, `ForwardClose` |
| 7 | `ImplicitReceiveBugTests` | oversized packet, wrong data item type, duplicate and stale sequence count |
| 8 | `ImplicitSendBugTests` | interval truncation, per-packet allocations, stop flag |
| 9 | `IdentityItemParsingTests`, `ListIdentityBugTests` | `State1`, truncated replies, and a truncated reply killing the process |
| 10 | `ListIdentityBugTests` | accumulating list, shared list instance, late replies, leaked sockets |
| 11 | `PathAndMulticastHelperBugTests` | 8-bit segment for exactly `0xFF` |
| 12 | `PathAndMulticastHelperBugTests` | class D/E device addresses must be rejected (a contract choice, see the test comment) |
| 13 | `TcpReplyFramingTests` | every item 6 scenario runs against all builders; `Item13_*` guards the request side |

## Found while writing them (not on the original list)

* `Extra_ListIdentity_SendsToTheDirectedBroadcastAddressWithoutThrowing`: `ListIdentity` throws
  `SocketException(AccessDenied)` on Linux because `UdpClient.EnableBroadcast` is never set. The item 9/10 `ListIdentity` tests
  are blocked by it and say so in their failure message.
* `Item07_ReopeningTheConnectionRightAfterClosing_*`: `udpClientReceiveClosed` is one flag per client, so `ForwardClose`
  followed by `ForwardOpen` makes the previous socket's last callback call `BeginReceive` on a disposed `UdpClient`.
* `Item07_PacketShorterThanTheRealTimeHeader_*`: with `T_O_RealTimeFormat = Header32Bit`, a 21-23 byte datagram gives a
  negative `Array.Copy` length.
* `Item08_ForwardClose_RightAfterForwardOpen_*`: `sendUDP` clears `stopUDP` as its first statement, so a `ForwardClose`
  that wins the race is lost and the thread sends forever.

## Not covered by a test

* Item 7, `WSAECONNRESET` from `EndReceive`: Windows only. The receive socket never sends, and ICMP port unreachable
  is delivered to the socket that sent the datagram (the separate send socket), so it may not apply at all.
* Item 7/8, memory visibility of `udpClientReceiveClosed` / `stopUDP`: not observable on x86/ARM, where the loop calls
  `Send`/`Sleep`. The observable defects around both flags are tested above.
* Item 7, re-arming `BeginReceive` before `EndReceive` (out-of-order callbacks): not deterministic. The duplicate/stale
  sequence tests cover its observable effect.
* Item 12, using the target's configured netmask instead of the address class: needs a new API to pin down.

## Crashes are tested in a child process

An unhandled exception on a threadpool thread terminates the process, and xunit would take the whole run with it.
Those tests (`IsolatedScenario`) start this test assembly again for one `Scenario_*` method (skipped in normal runs)
and fail if the log contains `[FATAL ERROR]`. xunit does not reliably set a failing exit code for such a crash, so the
log is what is checked.

## Fake target additions

`FakeEipTarget` gained `SplitReplyAt` (cut replies into separate TCP writes), `RawReply` (send arbitrary bytes) and an
encapsulation status parameter on `BuildSendRRDataReply`. `ImplicitHarness` and `ListIdentityResponder` are new.
The `ListIdentity` tests need an up Ethernet/Wi-Fi interface with IPv4 and a free UDP port 44818, and skip otherwise.
