#include "icmp.h"
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>

void handle_icmp(int tap_fd,
                 const struct eth_hdr *eth,
                 const struct ip_hdr *ip,
                 const uint8_t *payload,
                 size_t payload_len,
                 uint8_t *my_mac) {
    if (payload_len < ICMP_MIN_HLEN) return;

    const struct icmp_hdr *req = (const struct icmp_hdr *)payload;
    if (in_cksum(req, payload_len) != 0) return;
    if (req->type != ICMP_ECHO_REQUEST || req->code != 0) return;

    size_t ip_total = IPV4_MIN_HLEN + payload_len;
    size_t frame_len = ETH_HLEN + ip_total;
    if (frame_len > MAX_FRAME_SIZE) return;

    uint8_t rep_buf[MAX_FRAME_SIZE];
    struct eth_hdr *rep_eth = (struct eth_hdr *)rep_buf;
    struct ip_hdr  *rep_ip  = (struct ip_hdr *)(rep_buf + ETH_HLEN);
    struct icmp_hdr *rep_icmp = (struct icmp_hdr *)(rep_buf + ETH_HLEN + IPV4_MIN_HLEN);

    memcpy(rep_eth->dmac, eth->smac, ETH_ALEN);
    memcpy(rep_eth->smac, my_mac, ETH_ALEN);
    rep_eth->ethertype = htons(ETH_P_IP);

    rep_ip->ver_ihl = (4 << 4) | (IPV4_MIN_HLEN / 4);
    rep_ip->tos = 0;
    rep_ip->total_len = htons((uint16_t)ip_total);
    rep_ip->id = htons(0x1234);
    rep_ip->frag_offset = 0;
    rep_ip->ttl = 64;
    rep_ip->proto = IP_PROTO_ICMP;
    rep_ip->csum = 0;
    rep_ip->saddr = ip->daddr;
    rep_ip->daddr = ip->saddr;
    rep_ip->csum = in_cksum(rep_ip, IPV4_MIN_HLEN);

    memcpy(rep_icmp, req, payload_len);
    rep_icmp->type = ICMP_ECHO_REPLY;
    rep_icmp->code = 0;
    rep_icmp->csum = 0;
    rep_icmp->csum = in_cksum(rep_icmp, payload_len);

    if (write(tap_fd, rep_buf, frame_len) < 0) {
        perror("[ICMP] write failed");
    }
}
