#include "ipv4.h"
#include "icmp.h"
#include "tcp.h"
#include "udp.h"
#include <stdio.h>
#include <arpa/inet.h>

uint16_t in_cksum(const void *buf, size_t len) {
    const uint16_t *data = (const uint16_t *)buf;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *data++;
        len -= 2;
    }

    if (len == 1) {
        uint16_t last_byte = 0;
        *(uint8_t *)(&last_byte) = *(const uint8_t *)data;
        sum += last_byte;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

uint16_t checksum(const void *buf, size_t len) {
    return in_cksum(buf, len);
}

void handle_ipv4(int tap_fd, uint8_t *frame, size_t len, uint32_t my_ip, uint8_t *my_mac) {
    if (len < ETH_HLEN + IPV4_MIN_HLEN) return;

    struct eth_hdr *eth = (struct eth_hdr *)frame;
    struct ip_hdr *ip = (struct ip_hdr *)(frame + ETH_HLEN);

    if (ip_version(ip) != 4) return;

    uint8_t hlen = ip_ihl(ip);
    if (hlen < IPV4_MIN_HLEN || len < (size_t)(ETH_HLEN + hlen)) return;

    uint16_t total_len = ntohs(ip->total_len);
    if (total_len < hlen || len < (size_t)(ETH_HLEN + total_len)) return;

    if (in_cksum(ip, hlen) != 0) return;

    if (ip->daddr != my_ip) return;

    const uint8_t *payload = frame + ETH_HLEN + hlen;
    size_t payload_len = total_len - hlen;

    if (ip->proto == IP_PROTO_ICMP) {
        handle_icmp(tap_fd, eth, ip, payload, payload_len, my_mac);
    } else if (ip->proto == IP_PROTO_UDP) {
        handle_udp(tap_fd, eth, ip, payload, payload_len, my_mac);
    } else if (ip->proto == IP_PROTO_TCP) {
        handle_tcp(tap_fd, frame, len, my_mac);
    }
}
