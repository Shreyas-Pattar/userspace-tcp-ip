#ifndef UDP_H
#define UDP_H

#include "netdev.h"
#include "ipv4.h"

struct udp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t csum;
} __attribute__((packed));

void handle_udp(int tap_fd,
                const struct eth_hdr *eth,
                const struct ip_hdr *ip,
                const uint8_t *payload,
                size_t payload_len,
                uint8_t *my_mac);

#endif
