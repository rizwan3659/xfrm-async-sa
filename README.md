# xfrm-async-sa

Installing IPSec security associations (SAs) in the Linux kernel over
`NETLINK_XFRM`, in two ways:

- **sync**: send one `XFRM_MSG_NEWSA`, block until the kernel acks it, then
  send the next. This is how many control planes start out.
- **async**: keep up to *W* requests in flight and match each ack back to
  its request by netlink sequence number, in whatever order it arrives.

A P-CSCF creates IPSec SAs for every UE registration (3GPP TS 33.203), so SA
setup sits on the registration path. When it runs one request at a time, each
SA pays a full user-to-kernel-to-user round trip. Pipelining the requests
removes most of that wait.

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

## Results (mock kernel)

2-vCPU cloud VM, gcc 13, `-O2`, 20,000 SAs, window 64:

| Simulated kernel time per SA | sync | async (W=64) | speed-up |
| --- | --- | --- | --- |
| 0 us | 21,250 SA/s | 46,367 SA/s | 2.2x |
| 5 us | 19,460 SA/s | 34,301 SA/s | 1.8x |

The mock kernel handles requests one at a time on its own thread, like the
kernel's XFRM handler. So the gain here comes from removing round-trip
waits, not from parallel work. The ratio depends on how large the round
trip is compared with the kernel's own work per SA: real systems with more
context-switch and scheduling latency gain more.

**Not yet measured:** the real-kernel path. The CI and development VMs here
don't implement `NETLINK_XFRM` (they return `ENOSYS`). `--real` has been
written against the kernel UAPI but still needs a run on a full Linux host.

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
- **Acks are matched by sequence number, not by arrival order.** Acks with an
  unknown sequence number or a duplicate ack are ignored.
- **The ack parser distrusts its input.** Truncated messages, and messages
  whose length field exceeds the buffer, are rejected. The tests cover both.
- **One datagram can carry several netlink messages.** The receiver walks
  them with `NLMSG_OK` / `NLMSG_NEXT`.

## Not done yet

- Real-kernel benchmark numbers on a full Linux host
- Security policies (`XFRM_MSG_NEWPOLICY`) alongside SAs
- SA lifetimes, rekeying, and handling `XFRM_MSG_EXPIRE` events

MIT licensed.
