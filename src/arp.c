#include "arp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

static struct arp_entry arp_cache[ARP_CACHE_SIZE];

void arp_init(void) {
    memset(arp_cache, 0, sizeof(arp_cache));
}

void arp_cache_cleanup(void) {
    time_t now = time(NULL);
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (arp_cache[i].valid && (now - arp_cache[i].updated > ARP_CACHE_TTL)) {
            arp_cache[i].valid = 0;
            printf("[ARP] Evicted expired cache entry\n");
        }
    }
}

int arp_cache_lookup(uint32_t ip, uint8_t *mac_out) {
    arp_cache_cleanup();
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (arp_cache[i].valid && arp_cache[i].ip == ip) {
            memcpy(mac_out, arp_cache[i].mac, ETH_ALEN);
            return 0;
        }
    }
    return -1;
}

void arp_cache_update(uint32_t ip, const uint8_t *mac) {
    time_t now = time(NULL);
    int oldest_idx = 0;
    time_t oldest_time = now;

    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (arp_cache[i].valid && arp_cache[i].ip == ip) {
            memcpy(arp_cache[i].mac, mac, ETH_ALEN);
            arp_cache[i].updated = now;
            return;
        }
        if (!arp_cache[i].valid) {
            arp_cache[i].ip = ip;
            memcpy(arp_cache[i].mac, mac, ETH_ALEN);
            arp_cache[i].updated = now;
            arp_cache[i].valid = 1;
            printf("[ARP] Cached IP to MAC mapping\n");
            return;
        }
        if (arp_cache[i].updated < oldest_time) {
            oldest_time = arp_cache[i].updated;
            oldest_idx = i;
        }
    }

    /* Evict oldest */
    arp_cache[oldest_idx].ip = ip;
    memcpy(arp_cache[oldest_idx].mac, mac, ETH_ALEN);
    arp_cache[oldest_idx].updated = now;
    arp_cache[oldest_idx].valid = 1;
}

void handle_arp(int tap_fd, uint8_t *frame, size_t len, uint32_t my_ip, uint8_t *my_mac) {
    if (len < ETH_HLEN + sizeof(struct arp_hdr)) return;

    struct arp_hdr *arp = (struct arp_hdr *)(frame + ETH_HLEN);

    if (ntohs(arp->htype) != 1 || ntohs(arp->ptype) != ETH_P_IP ||
        arp->hlen != ETH_ALEN || arp->plen != 4) {
        return;
    }

    arp_cache_update(arp->sip, arp->smac);

    if (ntohs(arp->opcode) == ARP_OP_REQUEST && arp->dip == my_ip) {
        uint8_t reply[ETH_HLEN + sizeof(struct arp_hdr)];
        struct eth_hdr *rep_eth = (struct eth_hdr *)reply;
        struct arp_hdr *rep_arp = (struct arp_hdr *)(reply + ETH_HLEN);

        memcpy(rep_eth->dmac, arp->smac, ETH_ALEN);
        memcpy(rep_eth->smac, my_mac, ETH_ALEN);
        rep_eth->ethertype = htons(ETH_P_ARP);

        rep_arp->htype = htons(1);
        rep_arp->ptype = htons(ETH_P_IP);
        rep_arp->hlen = ETH_ALEN;
        rep_arp->plen = 4;
        rep_arp->opcode = htons(ARP_OP_REPLY);
        memcpy(rep_arp->smac, my_mac, ETH_ALEN);
        rep_arp->sip = my_ip;
        memcpy(rep_arp->dmac, arp->smac, ETH_ALEN);
        rep_arp->dip = arp->sip;

        if (write(tap_fd, reply, sizeof(reply)) < 0) {
            perror("[ARP] write failed");
        }
    }
}
