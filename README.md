# xfrm-async-sa

Installing IPSec security associations (SAs) in the Linux kernel over
`NETLINK_XFRM`, in two ways:

- **sync**: send one `XFRM_MSG_NEWSA`, block until the kernel acks it, then
  send the next. This is how many control planes start out.
- **async**: keep up to *W* requests in flight and match each ack back to
  its request by netlink sequence number, in whatever order it arrives.

P-CSCF access security involves multiple SAs and policies per UE security
context (3GPP TS 33.203). This project isolates state installation: it does
not implement registration, policy negotiation, or packet encryption.
Pipelining reduces application-level wait/receive overhead; it does not
make the kernel process requests in parallel. Real Netlink request work can
execute during send(), unlike the independently scheduled mock worker.

> This is a clean-room re-implementation of a technique I used in production
> at C-DOT (scaling P-CSCF IPSec SA handling). It contains no C-DOT code and
> no production numbers. The figures below come from this repository only.

## Build and run

```sh
make            # builds ./xfrm-bench
make test       # unit + integration tests against a mock kernel
make asan tsan  # the same tests under ASan/UBSan and ThreadSanitizer
make bench
```

```
./xfrm-bench [--count N] [--window W] [--service-us US] [--real]
```

`--real` talks to the running kernel. It needs root (`CAP_NET_ADMIN`) and a
kernel with `CONFIG_XFRM_USER`, installs N ESP SAs in transport mode
(`rfc4106(gcm(aes))`), then deletes them again. Run it only on a test machine.

## Historical results (mock kernel before this review)

2-vCPU cloud VM, gcc 13, `-O2`, 20,000 SAs, window 64:

| Simulated kernel time per SA | sync | async (W=64) | speed-up |
| --- | --- | --- | --- |
| 0 us | 21,250 SA/s | 46,367 SA/s | 2.2x |
| 5 us | 19,460 SA/s | 34,301 SA/s | 1.8x |

The mock kernel handles requests one at a time on its own thread, like the
kernel's XFRM handler. So the gain here comes from removing round-trip
waits, not from parallel work. The ratio depends on scheduling and service cost. These old observations
were not remeasured after the correctness and mock hash-table changes;
rerun the benchmark before using them to describe the revised code.

**Real-kernel correctness is now tested:** CI installs and deletes states in a
disposable Linux network namespace and verifies that a pre-existing SA
survives an EEXIST failure. This is a smoke test, not a throughput study or
an encrypted-traffic interoperability test. See [review evidence](docs/review.md).

```sh
sudo unshare -n sh tests/test_real.sh
```

The benchmark uses deterministic test keys. Use a disposable namespace,
never operational traffic. Cleanup deletes only ACK-confirmed installs;
a timed-out installation has unknown state and may remain until the test
namespace is destroyed. Cleanup failures cause a nonzero exit status.

## Study guide

Read [the complete walkthrough](docs/study-guide.md) for XFRM fundamentals,
wire layouts, scheduling invariants, error recovery, laboratory exercises,
and interview questions. [The review](docs/review.md) lists fixes and limits.
This is userspace Linux C using a kernel API, not a kernel module.

## Design

| File | What it does |
| --- | --- |
| `src/xfrm_msg.c` | Builds `XFRM_MSG_NEWSA` / `XFRM_MSG_DELSA` with an `XFRMA_ALG_AEAD` attribute; parses `NLMSG_ERROR` acks with length checks |
| `src/transport.c` | Real `NETLINK_XFRM` socket, and a mock kernel on a `SOCK_SEQPACKET` pair (duplicate SPI gives `EEXIST`, unknown SA gives `ESRCH`) |
| `src/sa_mgr.c` | Windowed pipeline: sequence-number correlation, per-SA error reporting, timeout handling |

Things to notice:

- **One SA failing never aborts the batch.** Each SA gets its own result
  (`0`, `-EEXIST`, `-ETIMEDOUT`, and so on). The tests check a duplicate
  inside a batch.
- **Acks are matched by sequence number, not by arrival order.** Each batch
  reserves fresh sequences on its transport. Unknown, duplicate, stale,
  and not-yet-sent sequence numbers cannot complete a request.
- **The ack parser distrusts its input.** Truncated messages, and messages
  whose length field exceeds the buffer, are rejected. The tests cover both.
- **One datagram can carry several netlink messages.** The receiver walks
  them with `NLMSG_OK` / `NLMSG_NEXT`.

- **Timeouts use per-request monotonic deadlines.** An unrelated datagram is
  not a timeout; a timeout is not proof the state was never installed.
- **Socket backpressure is handled while work is in flight.** Nonblocking
  sends yield to ACK draining on EAGAIN. Calls sharing a transport must
  be serialized. The public batch API itself still blocks its caller.

## Not done yet

- Real-kernel benchmark numbers on a full Linux host
- Security policies (`XFRM_MSG_NEWPOLICY`) alongside SAs
- Lifetime management, rekeying, and handling `XFRM_MSG_EXPIRE` events
- GETSA/dump reconciliation, restart recovery, and per-UE rollback
- Packet-level tests, IPv6, and operational key management

MIT licensed.
