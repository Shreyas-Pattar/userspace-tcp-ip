# Userspace TCP/IP Stack in C

A modular userspace network stack implemented from scratch in C on Linux, operating
on raw Ethernet frames via a TAP virtual interface (`/dev/net/tun`, `IFF_TAP | IFF_NO_PI`).
No kernel networking stack is used for packet processing — every layer from Ethernet
demux up through a basic HTTP response is handled in userspace code written for this
project.

Verified with AddressSanitizer, UndefinedBehaviorSanitizer, Valgrind, and an adversarial
Scapy/Pytest fuzzing suite.

---

## Architecture overview

```
       +-----------------------------------------------------------+
       |                     Linux Kernel                          |
       |  tap0 interface (10.0.0.1/24, 00:0c:29:ab:cd:01)          |
       +-----------------------------+-----------------------------+
                                     | Raw L2 Ethernet Frames
                                     v
       +-----------------------------------------------------------+
       |                 Userspace Stack (netstack)                |
       |               (10.0.0.2, 00:0c:29:ab:cd:ef)               |
       |                                                           |
       |   Ethernet Demux (src/tap.c, src/main.c)                  |
 L2    |   +---------------------+-------------------------+      |
       |   | ARP Handler         | IPv4 Parser              |      |
       |   | - Cache with TTL    | - RFC 1071 checksum      |      |
       |   | - LRU eviction      | - Length/bounds checks   |      |
       |   +---------------------+------------+-------------+     |
       |                                       |                  |
 L3/L4 |                 +---------------------+----------------+ |
       |                 |                     |                | |
       |                 v                     v                v |
       |           +-----------+        +-----------+    +------+-+
       |           | ICMP Echo |        | UDP Echo  |    | TCP TCB |
       |           | Responder |        |  Server   |    |  Table  |
       |           +-----------+        +-----------+    +------+-+
       |                                                        |  |
 L7    |                                                  +-----+--+
       |                                                  | HTTP   |
       |                                                  | (1.0-  |
       |                                                  | style) |
       |                                                  +--------+
       +-----------------------------------------------------------+
```

## Features

**Layer 2 (Data Link):**
- Raw Ethernet frame read/write over a Linux TAP interface (`IFF_NO_PI`).
- ARP resolution with a 32-entry cache, timestamped TTL-based expiry (60s), and
  LRU eviction when the cache is full.

**Layer 3 (Network):**
- RFC 1071 16-bit one's-complement Internet checksum, calculation and verification.
- Strict header/total-length invariant checks before trusting any field (prevents
  reading past the actual received frame on malformed input).
- ICMP Echo (ping) responder preserving identifier, sequence number, and payload.

**Layer 4 (Transport):**
- UDP Echo server with correct IPv4 pseudo-header checksum calculation.
- TCP Transmission Control Block (TCB) table tracking RFC 793 states (`LISTEN`,
  `SYN_RCVD`, `ESTABLISHED`, `FIN_WAIT_1`, `FIN_WAIT_2`, `CLOSE_WAIT`, `TIME_WAIT`,
  `CLOSED`), with sequence/ACK number tracking.

**Layer 7 (Application):**
- Minimal HTTP response dispatcher over an active TCP connection (see limitations —
  this is single-request, HTTP/1.0-style, not persistent).

**Memory safety:**
- Zero dynamic heap allocation in the packet-processing fast path.
- Verified with AddressSanitizer + UndefinedBehaviorSanitizer and Valgrind
  (`--leak-check=full`), both clean.
- Adversarial Scapy test suite: truncated headers, corrupted checksums, inconsistent
  length fields, and MTU-boundary frames — all handled without a crash.

---

## Directory structure

```
userspace-tcp-ip/
├── Makefile
├── .gitignore
├── README.md
├── include/
│   ├── arp.h
│   ├── icmp.h
│   ├── ipv4.h
│   ├── netdev.h
│   ├── tap.h
│   ├── tcp.h
│   └── udp.h
├── src/
│   ├── arp.c
│   ├── icmp.c
│   ├── ipv4.c
│   ├── main.c
│   ├── tap.c
│   ├── tcp.c
│   └── udp.c
└── tests/
    └── test_stack.py
```

## Getting started

### Prerequisites

Linux (Ubuntu 22.04+ recommended, native or VM), `gcc`, `make`, `valgrind`,
Python 3 with `scapy` and `pytest`:

```bash
sudo apt update
sudo apt install -y build-essential valgrind python3-scapy python3-pytest netcat-openbsd
```

### 1. TAP interface setup (once per boot)

```bash
sudo ip tuntap add dev tap0 mode tap user $USER
sudo ip link set dev tap0 up
sudo ip addr add 10.0.0.1/24 dev tap0
```

### 2. Build

```bash
make asan     # AddressSanitizer + UndefinedBehaviorSanitizer build
make debug    # debug build for Valgrind / GDB
```

### 3. Run

```bash
sudo ./netstack
```

## Verification

### Manual functional tests

```bash
ping -c 3 10.0.0.2
echo "Hello Netstack" | nc -u -w1 10.0.0.2 9999
printf "GET / HTTP/1.1\r\nHost: 10.0.0.2:8080\r\nConnection: close\r\n\r\n" | nc 10.0.0.2 8080
```

### Automated adversarial testing (Pytest + Scapy)

```bash
sudo pytest -v tests/test_stack.py
```

Covers: ARP resolution, ICMP echo correctness, UDP echo correctness, and a fuzz pass
over truncated IPv4/UDP headers, corrupted checksums, inconsistent length fields, and
max-MTU-boundary frames — confirming the stack neither crashes nor misbehaves on any
of them.

### Memory safety audit

```bash
sudo valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./netstack
```

Run the test suite from a second terminal while this is active, then `Ctrl+C` the
stack and confirm a clean `HEAP SUMMARY` (0 leaks, 0 errors).

---

## Known limitations (read before claiming RFC 793 compliance)

This stack demonstrates the core mechanics of TCP/IP from the wire up, but it is
**not** a complete, spec-compliant TCP implementation. Specifically:

1. **`in_cksum` uses a direct `uint16_t*` cast over the byte buffer**, which is
   technically undefined behavior under C's strict aliasing/alignment rules (works
   correctly on x86_64 due to how the buffers happen to be aligned in this specific
   layout, but is not portable to strict-alignment architectures like ARMv7 or
   SPARC). The portable fix is to read each 16-bit word via `memcpy` into a local
   variable instead of dereferencing a reinterpreted pointer directly.
2. **Single-request, HTTP/1.0-style behavior.** The TCP handler sends the HTTP
   response with the FIN flag piggybacked on the same segment and immediately begins
   connection teardown. It cannot handle `Connection: keep-alive`, pipelined
   requests, or multiple requests over one connection — each connection serves
   exactly one request, then closes.
3. **No `CLOSING` state / no simultaneous-close handling.** RFC 793's simultaneous-
   close path (`FIN_WAIT_1 → CLOSING → TIME_WAIT`, entered when a FIN arrives before
   this stack's own FIN has been ACKed) is not implemented. The current FSM assumes
   the more common case where one side closes first.
4. **`TIME_WAIT` is set and then immediately overwritten to `CLOSED`** on the next
   line of code, rather than being held for the standard 2×MSL interval. Real TCP
   holds this state to let delayed duplicate segments drain from the network before
   a connection's 4-tuple can be reused; this implementation has no timer subsystem
   to do that, so the state transition is effectively cosmetic.
5. **No retransmission or RTO (retransmission timeout) handling.** There is no
   unacknowledged-segment queue, so a dropped segment is never resent.
6. **No sliding window or out-of-order segment reassembly.** Segments are assumed to
   arrive in order; there is no reassembly buffer for packets that don't.
7. **Blocking I/O, single connection at a time** (via a fixed-size TCB table, no
   `epoll`/`poll`-based concurrency) — this is not designed to serve many concurrent
   TCP streams efficiently.

None of this is hidden to make the project look more complete than it is — these are
exactly the gaps a technical interviewer would probe for, and they're the genuine
next milestones (retransmission/RTO, sliding window, `CLOSING` state, and an
`epoll`-based event loop, in that order, would be the natural continuation of this
project).

## Tech stack

C11 (`gcc`, `-Wall -Wextra -Werror -pedantic`), Linux TAP/TUN driver, Python 3
(Scapy, pytest), Valgrind, AddressSanitizer/UndefinedBehaviorSanitizer. No paid
tools required.
