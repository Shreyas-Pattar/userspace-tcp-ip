#ifndef TCP_H
#define TCP_H

#include <stdint.h>
#include <sys/types.h>
#include "ipv4.h"

#define TCP_MAX_TCBS 16

/* TCP Flags */
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

/* TCP FSM States (RFC 793) */
typedef enum {
    TCP_CLOSED = 0,
    TCP_LISTEN,
    TCP_SYN_RCVD,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_TIME_WAIT
} tcp_state_t;

struct tcp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset_reserved;
    uint8_t  flags;
    uint16_t win;
    uint16_t csum;
    uint16_t urp;
} __attribute__((packed));

struct tcp_pseudo_hdr {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t tcp_len;
} __attribute__((packed));

/* Transmission Control Block (TCB) */
struct tcb {
    tcp_state_t state;
    uint32_t local_ip;
    uint32_t remote_ip;
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t snd_una;
    uint32_t snd_nxt;
    uint32_t snd_wnd;
    uint32_t rcv_nxt;
    uint32_t rcv_wnd;
};

static inline uint8_t tcp_offset(struct tcp_hdr *tcp) {
    return (tcp->data_offset_reserved >> 4) * 4;
}

static inline void tcp_set_offset(struct tcp_hdr *tcp, uint8_t bytes) {
    tcp->data_offset_reserved = ((bytes / 4) << 4);
}

void tcp_init(void);
struct tcb *tcb_lookup(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport);
struct tcb *tcb_alloc(uint32_t local_ip, uint16_t local_port);
void handle_tcp(int tap_fd, uint8_t *frame, ssize_t len, uint8_t *my_mac);

#endif
