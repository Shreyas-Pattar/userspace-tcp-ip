#ifndef ARP_H
#define ARP_H

#include "netdev.h"
#include <time.h>

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2
#define ARP_CACHE_SIZE 32
#define ARP_CACHE_TTL  60

struct arp_hdr {
    uint16_t htype;
    uint16_t ptype;
    uint8_t  hlen;
    uint8_t  plen;
    uint16_t opcode;
    uint8_t  smac[ETH_ALEN];
    uint32_t sip;
    uint8_t  dmac[ETH_ALEN];
    uint32_t dip;
} __attribute__((packed));

struct arp_entry {
    uint32_t ip;
    uint8_t  mac[ETH_ALEN];
    time_t   updated;
    int      valid;
};

void arp_init(void);
void arp_cache_cleanup(void);
int  arp_cache_lookup(uint32_t ip, uint8_t *mac_out);
void arp_cache_update(uint32_t ip, const uint8_t *mac);
void handle_arp(int tap_fd, uint8_t *frame, size_t len, uint32_t my_ip, uint8_t *my_mac);

#endif
