#ifndef ICMP_H
#define ICMP_H

#include "netdev.h"
#include "ipv4.h"

#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY   0

struct icmp_hdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t csum;
    uint16_t id;
    uint16_t seq;
} __attribute__((packed));

void handle_icmp(int tap_fd,
                 const struct eth_hdr *eth,
                 const struct ip_hdr *ip,
                 const uint8_t *payload,
                 size_t payload_len,
                 uint8_t *my_mac);

#endif
