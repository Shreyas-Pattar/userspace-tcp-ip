#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "tcp.h"
#include "ipv4.h"
#include "netdev.h"

static struct tcb tcbs[TCP_MAX_TCBS];

static const char *state_to_str(tcp_state_t state) {
    switch (state) {
        case TCP_CLOSED:      return "CLOSED";
        case TCP_LISTEN:      return "LISTEN";
        case TCP_SYN_RCVD:    return "SYN_RCVD";
        case TCP_ESTABLISHED: return "ESTABLISHED";
        case TCP_FIN_WAIT_1:  return "FIN_WAIT_1";
        case TCP_FIN_WAIT_2:  return "FIN_WAIT_2";
        case TCP_CLOSE_WAIT:  return "CLOSE_WAIT";
        case TCP_LAST_ACK:    return "LAST_ACK";
        case TCP_TIME_WAIT:   return "TIME_WAIT";
        default:              return "UNKNOWN";
    }
}

void tcp_init(void) {
    memset(tcbs, 0, sizeof(tcbs));
    tcbs[0].state = TCP_LISTEN;
    tcbs[0].local_port = 8080;
    tcbs[0].rcv_wnd = 65535;
    printf("[TCP] Initialized listening socket on port 8080 (state: LISTEN)\n");
}

struct tcb *tcb_lookup(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport) {
    struct tcb *listen_match = NULL;
    for (int i = 0; i < TCP_MAX_TCBS; i++) {
        if (tcbs[i].state == TCP_CLOSED) continue;

        if (tcbs[i].remote_ip == saddr &&
            tcbs[i].local_ip == daddr &&
            tcbs[i].remote_port == sport &&
            tcbs[i].local_port == dport) {
            return &tcbs[i];
        }

        if (tcbs[i].state == TCP_LISTEN && tcbs[i].local_port == dport) {
            listen_match = &tcbs[i];
        }
    }
    return listen_match;
}

struct tcb *tcb_alloc(uint32_t local_ip, uint16_t local_port) {
    for (int i = 1; i < TCP_MAX_TCBS; i++) {
        if (tcbs[i].state == TCP_CLOSED) {
            tcbs[i].local_ip = local_ip;
            tcbs[i].local_port = local_port;
            tcbs[i].rcv_wnd = 65535;
            return &tcbs[i];
        }
    }
    return NULL;
}

static uint16_t tcp_checksum(struct ip_hdr *ip, struct tcp_hdr *tcp, int tcp_len) {
    struct tcp_pseudo_hdr ph;
    memset(&ph, 0, sizeof(ph));
    ph.saddr = ip->saddr;
    ph.daddr = ip->daddr;
    ph.zero = 0;
    ph.proto = IP_PROTO_TCP;
    ph.tcp_len = htons((uint16_t)tcp_len);

    uint8_t buf[BUF_SIZE];
    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf + sizeof(ph), tcp, tcp_len);

    return in_cksum(buf, sizeof(ph) + tcp_len);
}

static void tcp_send_segment(int tap_fd, uint8_t *frame, struct tcb *tcb,
                             uint8_t flags, const uint8_t *payload, int payload_len,
                             uint8_t *my_mac) {
    struct eth_hdr *eth = (struct eth_hdr *)frame;
    struct ip_hdr *ip = (struct ip_hdr *)(frame + ETH_HLEN);
    int ip_hdr_len = ip_ihl(ip);
    struct tcp_hdr *tcp = (struct tcp_hdr *)(frame + ETH_HLEN + ip_hdr_len);

    memcpy(eth->dmac, eth->smac, ETH_ALEN);
    memcpy(eth->smac, my_mac, ETH_ALEN);

    uint32_t tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;
    ip->ttl = 64;

    tcp->sport = htons(tcb->local_port);
    tcp->dport = htons(tcb->remote_port);
    tcp->seq = htonl(tcb->snd_nxt);
    tcp->ack = htonl(tcb->rcv_nxt);
    tcp_set_offset(tcp, sizeof(struct tcp_hdr));
    tcp->flags = flags;
    tcp->win = htons(tcb->rcv_wnd);
    tcp->urp = 0;

    if (payload && payload_len > 0) {
        memcpy((uint8_t *)tcp + sizeof(struct tcp_hdr), payload, payload_len);
    }

    int tcp_len = sizeof(struct tcp_hdr) + payload_len;
    ip->total_len = htons(ip_hdr_len + tcp_len);
    ip->csum = 0;
    ip->csum = in_cksum(ip, ip_hdr_len);

    tcp->csum = 0;
    tcp->csum = tcp_checksum(ip, tcp, tcp_len);

    ssize_t out_len = ETH_HLEN + ip_hdr_len + tcp_len;
    if (write(tap_fd, frame, out_len) < 0) {
        perror("write to tap failed");
    }

    if (flags & TCP_SYN) tcb->snd_nxt++;
    if (flags & TCP_FIN) tcb->snd_nxt++;
    tcb->snd_nxt += payload_len;
}

void handle_tcp(int tap_fd, uint8_t *frame, ssize_t len, uint8_t *my_mac) {
    (void)len;
    struct ip_hdr *ip = (struct ip_hdr *)(frame + ETH_HLEN);
    int ip_hdr_len = ip_ihl(ip);

    struct tcp_hdr *tcp = (struct tcp_hdr *)(frame + ETH_HLEN + ip_hdr_len);
    int tcp_total_len = ntohs(ip->total_len) - ip_hdr_len;
    int tcp_hdr_len = tcp_offset(tcp);

    if (tcp_total_len < (int)sizeof(struct tcp_hdr)) return;

    uint16_t src_port = ntohs(tcp->sport);
    uint16_t dst_port = ntohs(tcp->dport);
    uint32_t seg_seq = ntohl(tcp->seq);
    uint32_t seg_ack = ntohl(tcp->ack);
    int payload_len = tcp_total_len - tcp_hdr_len;

    struct tcb *entry = tcb_lookup(ip->saddr, ip->daddr, src_port, dst_port);
    if (!entry) {
        printf("[TCP] No match for %u -> %u\n", src_port, dst_port);
        return;
    }

    printf("[TCP] [%s] Packet from port %u | Flags: 0x%02x | Seq: %u | Ack: %u\n",
           state_to_str(entry->state), src_port, tcp->flags, seg_seq, seg_ack);

    switch (entry->state) {
        case TCP_LISTEN: {
            if (tcp->flags & TCP_SYN) {
                struct tcb *conn = tcb_alloc(ip->daddr, dst_port);
                if (!conn) {
                    printf("[TCP] Out of TCB slots\n");
                    return;
                }
                conn->remote_ip = ip->saddr;
                conn->remote_port = src_port;
                conn->rcv_nxt = seg_seq + 1;
                conn->snd_nxt = 500000;
                conn->state = TCP_SYN_RCVD;

                printf("[TCP] [LISTEN -> SYN_RCVD] for port %u\n", src_port);
                tcp_send_segment(tap_fd, frame, conn, TCP_SYN | TCP_ACK, NULL, 0, my_mac);
            }
            break;
        }

        case TCP_SYN_RCVD: {
            if (tcp->flags & TCP_ACK) {
                if (seg_ack == entry->snd_nxt) {
                    entry->state = TCP_ESTABLISHED;
                    printf("[TCP] [SYN_RCVD -> ESTABLISHED] for port %u\n", src_port);
                }
            }
            break;
        }

        case TCP_ESTABLISHED: {
            if (payload_len > 0) {
                char *data = (char *)((uint8_t *)tcp + tcp_hdr_len);
                printf("[TCP] Received %d payload bytes from port %u:\n%.*s\n",
                       payload_len, src_port, payload_len, data);

                entry->rcv_nxt = seg_seq + payload_len;

                const char *body = "Hello from userspace TCP stack with TCB state tracking!\n";
                char resp[512];
                int resp_len = snprintf(resp, sizeof(resp),
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Length: %zu\r\n"
                    "Connection: close\r\n\r\n%s",
                    strlen(body), body);

                entry->state = TCP_FIN_WAIT_1;
                printf("[TCP] [ESTABLISHED -> FIN_WAIT_1] for port %u\n", src_port);
                tcp_send_segment(tap_fd, frame, entry, TCP_ACK | TCP_PSH | TCP_FIN,
                                 (uint8_t *)resp, resp_len, my_mac);
            } else if (tcp->flags & TCP_FIN) {
                entry->rcv_nxt = seg_seq + 1;
                entry->state = TCP_CLOSE_WAIT;
                printf("[TCP] [ESTABLISHED -> CLOSE_WAIT] for port %u\n", src_port);
                tcp_send_segment(tap_fd, frame, entry, TCP_ACK, NULL, 0, my_mac);
            }
            break;
        }

        case TCP_FIN_WAIT_1: {
            if ((tcp->flags & TCP_ACK) && (seg_ack == entry->snd_nxt)) {
                entry->state = TCP_FIN_WAIT_2;
                printf("[TCP] [FIN_WAIT_1 -> FIN_WAIT_2] for port %u\n", src_port);
            }
            if (tcp->flags & TCP_FIN) {
                entry->rcv_nxt = seg_seq + 1;
                if (entry->state == TCP_FIN_WAIT_2) {
                    entry->state = TCP_TIME_WAIT;
                    printf("[TCP] [FIN_WAIT_2 -> TIME_WAIT] for port %u\n", src_port);
                    tcp_send_segment(tap_fd, frame, entry, TCP_ACK, NULL, 0, my_mac);
                    entry->state = TCP_CLOSED;
                    printf("[TCP] Connection CLOSED for port %u\n", src_port);
                }
            }
            break;
        }

        case TCP_FIN_WAIT_2: {
            if (tcp->flags & TCP_FIN) {
                entry->rcv_nxt = seg_seq + 1;
                entry->state = TCP_TIME_WAIT;
                printf("[TCP] [FIN_WAIT_2 -> TIME_WAIT] for port %u\n", src_port);
                tcp_send_segment(tap_fd, frame, entry, TCP_ACK, NULL, 0, my_mac);
                entry->state = TCP_CLOSED;
                printf("[TCP] Connection CLOSED for port %u\n", src_port);
            }
            break;
        }

        default:
            break;
    }
}
