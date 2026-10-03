# userspace-tcp-ip
A deterministic, zero-heap userspace TCP/IP stack in C using Linux TAP (/dev/net/tun). Implements ARP, IPv4, ICMP, UDP echo, and TCP TCB state tracking. Fuzz-tested with Scapy; verified 0 leaks and 0 errors under ASan &amp; Valgrind.
