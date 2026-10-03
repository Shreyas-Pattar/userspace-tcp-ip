#include "udp.h"
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>

struct pseudo_hdr {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t length;
} __attribute__((packed));

static uint16_t udp_checksum(uint32_t saddr, uint32_t daddr, const struct udp_hdr *udp, size_t len) {
    struct pseudo_hdr ph;
    ph.saddr = saddr;
    ph.daddr = daddr;
    ph.zero = 0;
    ph.proto = 17;
    ph.length = htons((uint16_t)len);

    uint8_t buf[MAX_FRAME_SIZE];
    if (sizeof(ph) + len > sizeof(buf)) return 0;

    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf + sizeof(ph), udp, len);

    return in_cksum(buf, sizeof(ph) + len);
}

void handle_udp(int tap_fd,
                const struct eth_hdr *eth,
                const struct ip_hdr *ip,
                const uint8_t *payload,
                size_t payload_len,
                uint8_t *my_mac) {
    if (payload_len < UDP_HLEN) return;

    const struct udp_hdr *req_udp = (const struct udp_hdr *)payload;
    uint16_t ulen = ntohs(req_udp->len);

    if (ulen < UDP_HLEN || ulen > payload_len) return;

    if (req_udp->csum != 0) {
        if (udp_checksum(ip->saddr, ip->daddr, req_udp, ulen) != 0) {
            return;
        }
    }

    size_t reply_ip_total = IPV4_MIN_HLEN + ulen;
    size_t reply_frame_len = ETH_HLEN + reply_ip_total;
    if (reply_frame_len > MAX_FRAME_SIZE) return;

    uint8_t reply_buf[MAX_FRAME_SIZE];
    struct eth_hdr *rep_eth = (struct eth_hdr *)reply_buf;
    struct ip_hdr  *rep_ip  = (struct ip_hdr *)(reply_buf + ETH_HLEN);
    struct udp_hdr *rep_udp = (struct udp_hdr *)(reply_buf + ETH_HLEN + IPV4_MIN_HLEN);

    /* L2 */
    memcpy(rep_eth->dmac, eth->smac, ETH_ALEN);
    memcpy(rep_eth->smac, my_mac, ETH_ALEN);
    rep_eth->ethertype = htons(ETH_P_IP);

    /* L3 */
    rep_ip->ver_ihl = (4 << 4) | (IPV4_MIN_HLEN / 4);
    rep_ip->tos = 0;
    rep_ip->total_len = htons((uint16_t)reply_ip_total);
    rep_ip->id = htons(0x5678);
    rep_ip->frag_offset = 0;
    rep_ip->ttl = 64;
    rep_ip->proto = 17;
    rep_ip->csum = 0;
    rep_ip->saddr = ip->daddr;
    rep_ip->daddr = ip->saddr;
    rep_ip->csum = in_cksum(rep_ip, IPV4_MIN_HLEN);

    /* L4 UDP Echo */
    rep_udp->sport = req_udp->dport;
    rep_udp->dport = req_udp->sport;
    rep_udp->len = req_udp->len;
    rep_udp->csum = 0;

    const uint8_t *req_data = payload + UDP_HLEN;
    uint8_t *rep_data = reply_buf + ETH_HLEN + IPV4_MIN_HLEN + UDP_HLEN;
    memcpy(rep_data, req_data, ulen - UDP_HLEN);

    rep_udp->csum = udp_checksum(rep_ip->saddr, rep_ip->daddr, rep_udp, ulen);
    if (rep_udp->csum == 0) rep_udp->csum = 0xFFFF;

    printf("[UDP] Echoing back %u bytes (port %u -> %u)\n",
           ulen - UDP_HLEN, ntohs(rep_udp->sport), ntohs(rep_udp->dport));

    if (write(tap_fd, reply_buf, reply_frame_len) < 0) {
        perror("[UDP] write failed");
    }
}
