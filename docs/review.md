# XFRM repository review

Reviewed on 22 September 2026 against baseline `4a31962`.

The repository is a compact C userspace experiment with a useful separation
between encoding, transport, and scheduling. The review found correctness
issues in the asynchronous manager, mock, and benchmark cleanup. The fixes
keep that structure and add regression tests instead of expanding into an
unverified IMS implementation.

## Findings addressed

| Priority | Original behavior | Change and evidence |
| --- | --- | --- |
| High | Every batch started at the same sequence, allowing stale replies to complete later operations | Fresh per-transport ranges; late-reply and exhaustion tests |
| High | ACK matching included requests not yet sent | Match only sent pending entries; future-sequence test |
| High | Blocking sends could stop ACK draining under queue pressure | Nonblocking sends, EAGAIN drain/retry; fake backpressure and 5,000-entry window tests |
| High | Real cleanup deleted every requested identity, including EEXIST collisions | Delete only confirmed successful installs; real namespace test preserves a pre-existing SA |
| Medium | Zero matching ACKs immediately expired all outstanding requests | Per-request monotonic deadlines; unrelated/stale/drop/continuous-noise tests |
| Medium | Mock occupancy marker overwrote a destination-address bit | Separate slot state; previously colliding addresses coexist |
| Medium | Deleted mock slots were never reused | Tombstone reuse; 70,000 distinct insert/delete pairs |
| Medium | ACK parser assumed aligned input and accepted impossible positive errors | Copy headers, validate result domain; unaligned/positive/INT_MIN tests |
| Medium | Datagram truncation and peer closure were not distinguished from useful input/timeout | recvmsg checks MSG_TRUNC and EOF; send suppresses SIGPIPE |
| Medium | CLI accepted trailing junk, signed values, truncation and extra arguments | Strict range-checked conversion; shell CLI tests |

Other changes: report successful installs per second, surface cleanup failures,
skip the asynchronous real run after a failed synchronous run, retain timeout
budgets across EINTR, and document the builder alignment requirement.

## Validation

The development host is Windows. Linux compilation and execution ran in
GitHub Actions, not locally. The initial code validation at `127818d` passed:

- GCC and Clang unit/scripted/mock tests.
- AddressSanitizer and UndefinedBehaviorSanitizer with both compilers.
- ThreadSanitizer with both compilers.
- CLI invalid-input checks and 5,000-SA mock benchmark smoke runs.
- Real NETLINK_XFRM state installation/deletion and EEXIST preservation,
  using `sudo unshare -n sh tests/test_real.sh`.

[Initial passing run](https://github.com/rizwan3659/xfrm-async-sa/actions/runs/35706266027).
The final code validation at `f17ef11` also passed all three jobs:
[final code validation](https://github.com/rizwan3659/xfrm-async-sa/actions/runs/35708058785).
This includes the warning cleanups after the first run. The remaining
packaging changes add the printable PDF and documentation links only.

The scripted transport specifically tests out-of-order, duplicate, packed,
unknown, unsent and stale ACKs, missing ACKs, endless unrelated ACKs, EAGAIN,
send failure, zero timeout and sequence exhaustion. The normal FIFO mock
alone cannot establish those behaviors.

## Limits and follow-up work

This remains a batch demonstration, not a production IPsec controller. The
public functions block their caller; "async" describes pipelined requests.
One caller owns a transport at a time. An EAGAIN with nothing in flight
returns an error; a general service could add POLLOUT plus a send deadline.

Timeout begins after send returns, and is not an upper bound on kernel work
inside send. Fatal errors preserve known results but pending entries do not
distinguish unsent requests from unknown sent outcomes. No reconciliation
or automatic retry is implemented. Do not assume failed batches leave no
kernel state.

Ownership based on a successful install ACK is sufficient for an isolated,
single-writer lab. It is not a lease: a competing process could replace the
same identity between installation and deletion. Real mode must remain in a
disposable namespace.

The manager scans deadlines between the first unresolved request and the
last sent request. With a delayed early request, this can repeatedly scan
completed entries. A long-running service should use a bounded pending map
and an appropriate timer structure. The mock has fixed capacity and is not
a faithful kernel performance model.

No encrypted packet exchange, policy installation, IPv6, rekey, expiry-event
handling, restart recovery, HA fencing or IMS conformance is established.
The supplied deterministic keys are test fixtures, not an operational key
management mechanism. The original README performance figures remain
historical; neither those figures nor the smoke-test timings validate
production latency claims.

Code review, fixes, regression tests, and the study guide were prepared with
AI assistance. The tests and linked runs are the reproducible evidence.
