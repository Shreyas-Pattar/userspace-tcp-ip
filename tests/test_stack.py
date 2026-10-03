import pytest
from scapy.all import Ether, ARP, IP, ICMP, UDP, Raw, srp1, sendp, conf

conf.iface = "tap0"
conf.verb = 0

TAP_IP = "10.0.0.2"
TAP_MAC = "00:0c:29:ab:cd:ef"
HOST_IP = "10.0.0.1"
HOST_MAC = "00:0c:29:ab:cd:01"

def test_arp_resolution():
    """Verify ARP request yields a valid ARP reply with our userspace MAC."""
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=HOST_MAC) / ARP(
        op="who-has", hwsrc=HOST_MAC, psrc=HOST_IP, pdst=TAP_IP
    )
    reply = srp1(pkt, timeout=1.0)
    assert reply is not None, "ARP request timed out"
    assert reply.haslayer(ARP)
    assert reply[ARP].op == 2
    assert reply[ARP].hwsrc == TAP_MAC

def test_icmp_ping():
    """Verify ICMP echo reply matches payload."""
    payload = b"StackPingTest123"
    pkt = Ether(dst=TAP_MAC, src=HOST_MAC) / IP(src=HOST_IP, dst=TAP_IP) / ICMP(id=0x42, seq=1) / Raw(load=payload)
    reply = srp1(pkt, timeout=1.0)
    assert reply is not None, "Ping timed out"
    assert reply.haslayer(ICMP)
    assert reply[ICMP].type == 0
    assert reply[Raw].load == payload

def test_udp_echo():
    """Verify UDP echo reflects exact payload back."""
    payload = b"AdversarialEchoCheck"
    pkt = Ether(dst=TAP_MAC, src=HOST_MAC) / IP(src=HOST_IP, dst=TAP_IP) / UDP(sport=5000, dport=9999) / Raw(load=payload)
    reply = srp1(pkt, timeout=1.0)
    assert reply is not None, "UDP echo timed out"
    assert reply.haslayer(UDP)
    assert reply[UDP].sport == 9999
    assert reply[UDP].dport == 5000
    assert reply[Raw].load == payload

def test_adversarial_malformed_packets():
    """Fuzz with broken headers, truncated frames, and bad checksums.
    If AddressSanitizer doesn't abort and stack still responds, test passes."""

    for cut in range(1, 20):
        raw = bytes(Ether(dst=TAP_MAC, src=HOST_MAC) / IP(src=HOST_IP, dst=TAP_IP))[: 14 + cut]
        sendp(Ether(raw))

    bad_ip = Ether(dst=TAP_MAC, src=HOST_MAC) / IP(src=HOST_IP, dst=TAP_IP, chksum=0xBEEF) / ICMP()
    sendp(bad_ip)

    for cut in range(1, 8):
        raw = bytes(Ether(dst=TAP_MAC, src=HOST_MAC) / IP(src=HOST_IP, dst=TAP_IP, proto=17)) + (b"\x00" * cut)
        sendp(Ether(raw))

    bad_udp = Ether(dst=TAP_MAC, src=HOST_MAC) / IP(src=HOST_IP, dst=TAP_IP) / UDP(sport=1234, dport=9999, chksum=0xDEAD) / Raw(load=b"drop")
    sendp(bad_udp)

    inconsistent_len = Ether(dst=TAP_MAC, src=HOST_MAC) / IP(src=HOST_IP, dst=TAP_IP, len=2000) / UDP(sport=1111, dport=9999) / Raw(load=b"short")
    sendp(inconsistent_len)

    max_mtu_pkt = Ether(dst=TAP_MAC, src=HOST_MAC) / IP(src=HOST_IP, dst=TAP_IP) / UDP(sport=2222, dport=9999) / Raw(load=b"M" * 1472)
    sendp(max_mtu_pkt)

    test_icmp_ping()