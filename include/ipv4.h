#ifndef IPV4_H
#define IPV4_H

#include "netdev.h"

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP  6
#define IP_PROTO_UDP  17

struct ip_hdr {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_offset;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t csum;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((packed));

static inline uint8_t ip_ihl(const struct ip_hdr *ip) {
    return (ip->ver_ihl & 0x0F) * 4;
}

static inline uint8_t ip_version(const struct ip_hdr *ip) {
    return (ip->ver_ihl >> 4) & 0x0F;
}

uint16_t checksum(const void *buf, size_t len);
void handle_ipv4(int tap_fd, uint8_t *frame, size_t len, uint32_t my_ip, uint8_t *my_mac);

#endif
