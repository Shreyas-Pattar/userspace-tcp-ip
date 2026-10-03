#ifndef NETDEV_H
#define NETDEV_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#define ETH_ALEN       6
#define ETH_HLEN       14
#define ETH_P_IP       0x0800
#define ETH_P_ARP      0x0806

#define IPV4_MIN_HLEN  20
#define ICMP_MIN_HLEN  8
#define UDP_HLEN       8
#define MAX_FRAME_SIZE 1518

#define BUF_SIZE       2048

struct eth_hdr {
    uint8_t  dmac[ETH_ALEN];
    uint8_t  smac[ETH_ALEN];
    uint16_t ethertype;
} __attribute__((packed));

uint16_t in_cksum(const void *buf, size_t len);

#endif
